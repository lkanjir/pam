using System.Data.Common;
using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Authorization;
using Application.Principals;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class PrincipalDisableTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Disable_CurrentVersion_DisablesWithOneAuditAndRetainsAssignments()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        var entitlement = await SeedEntitlementAsync(test);
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        {
            PrincipalId = target.Id,
            EntitlementId = entitlement.Id,
            IsEnabled = true
        });
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string original = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var principal = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(principal);
        Assert.False(principal.IsEnabled);
        Assert.Equal(target.PublicId, principal.Id);
        Assert.Equal(test.Clock.Now, principal.ModifiedAt);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(original, response.Headers.ETag.Tag);
        Assert.False(await test.Database.Context.Principals.Where(value => value.Id == target.Id).Select(value => value.IsEnabled).SingleAsync());
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == target.Id && value.Role.Code == "user"));
        Assert.True(await test.Database.Context.EligibilityRules.AnyAsync(value => value.PrincipalId == target.Id && value.IsEnabled));
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "principal.disabled");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.Equal(test.Clock.Now.UtcDateTime, audit.OccurredAt);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.True(metadata.RootElement.GetProperty("before").GetProperty("isEnabled").GetBoolean());
        Assert.False(metadata.RootElement.GetProperty("after").GetProperty("isEnabled").GetBoolean());
        Assert.Equal(target.PublicId, metadata.RootElement.GetProperty("after").GetProperty("id").GetGuid());
        Assert.Equal("Policy review", metadata.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Disable_CurrentStateRetry_DoesNotChangeVersionOrDuplicateAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        string url = $"/api/principals/{target.PublicId}/disable";
        using var first = await test.Client.PostAsJsonAsync(url, Reason());
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.NotNull(first.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(first.Headers.ETag);

        // Act
        using var retry = await test.Client.PostAsJsonAsync(url, new ChangePrincipalStatusRequest { Reason = "Retry after lost response" });

        // Assert
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "principal.disabled"));
    }

    [Fact]
    public async Task Disable_AccountWithRetainedCookie_RejectsItsNextAuthenticatedRequest()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        await using var targetApp = await SessionTestHost.CreateSessionServerAsync(test.Database, test.Clock,
            target.Id.ToString(CultureInfo.InvariantCulture), redis.Connection);
        using var targetClient = targetApp.GetTestClient();
        using var login = await targetClient.GetAsync("/login");
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        SessionTestHost.UpdateCookie(targetClient, login);
        using var before = await targetClient.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var disabled = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());
        using var retained = await targetClient.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, retained.StatusCode);
        Assert.Null(retained.Headers.Location);
        var session = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking()
            .SingleAsync(value => value.PrincipalId == target.Id);
        Assert.Equal("access_changed", session.EndReason);
        Assert.Equal(test.Clock.Now.UtcDateTime, session.EndedAt);
    }

    [Fact]
    public async Task Disable_UnknownMapping_ReturnsNotFoundWithoutChangingAnotherAccount()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{Guid.NewGuid()}/disable", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(response.Headers.ETag);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Fact]
    public async Task Disable_OpenApi_DeclaresRequiredPrincipalVersionAndSecurityErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/disable").GetProperty("post");
        Assert.Equal("Principal.Disable", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(),
            parameter => parameter.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        var responses = operation.GetProperty("responses");
        Assert.True(responses.TryGetProperty("403", out _));
        Assert.True(responses.TryGetProperty("409", out _));
        Assert.True(responses.TryGetProperty("412", out _));
        Assert.True(responses.TryGetProperty("428", out _));
    }

    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task Disable_WithoutCurrentPermissionOrFreshSession_LeavesTargetEnabled(string role, bool signIn,
        bool timestamp, int age, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: role.Length == 0 ? [] : [role]);
        var target = await CreateTargetAsync(test);
        if (signIn)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: timestamp);
        }
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
        if (signIn && role == "admin")
        {
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("recent_auth_required", problem.RootElement.GetProperty("code").GetString());
        }
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("W/\"00000001\"", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task Disable_InvalidOrStalePrecondition_LeavesTargetEnabled(string? etag, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        if (etag is not null)
        {
            test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", etag);
        }

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Fact]
    public async Task Disable_SelfChange_ProtectsTheOnlyEnabledAdmin()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid id = await test.Database.Context.Principals.Where(value => value.Id == test.ActorId).Select(value => value.PublicId).SingleAsync();
        await SetVersionAsync(test, id);

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{id}/disable", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("self_change_forbidden", problem.RootElement.GetProperty("code").GetString());
        await AssertUnchangedAsync(test, test.ActorId);
    }

    [Fact]
    public async Task Disable_AuditRejected_RollsBackStatusAndVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_disable CHECK (event_type <> 'principal.disabled')");

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task Disable_InvalidRequestBoundary_LeavesTargetEnabled(string fault)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        if (fault == "csrf")
        {
            test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        }
        var request = new ChangePrincipalStatusRequest
        {
            Reason = fault switch { "empty-reason" => string.Empty, "long-reason" => new string('x', 501), _ => "Review" }
        };

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("public-id", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task Disable_DirectCaller_RechecksCurrentAuthorityAndValidation(string fault, PrincipalWriteKind expected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await CreateTargetAsync(test);
        var principal = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var snapshot = Snapshot(principal);
        if (fault == "role")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == test.ActorId).ExecuteDeleteAsync();
        }
        if (fault == "disabled")
        {
            await test.Database.Context.Principals.Where(value => value.Id == test.ActorId)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, false));
        }
        if (fault == "public-id")
        {
            snapshot = snapshot with { PublicId = Guid.NewGuid() };
        }
        var actor = new AdministrativeActor(snapshot, fault == "freshness" ? test.Clock.Now.AddMinutes(-11) : test.Clock.Now);
        await using var services = test.CreateScope();
        var service = new PrincipalAdministrationService(test.Database.Context, test.Clock,
            services.ServiceProvider.GetRequiredService<ISessionTicketStore>());
        var request = fault == "reason" ? new ChangePrincipalStatusRequest { Reason = string.Empty } : Reason();

        // Act
        var result = await service.DisableAsync(target.PublicId, request, actor, target.Version, "direct-disable");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Principal);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Disable_TwoAdminsCrossDisabling_OnlyFirstCommitsAndOneAdminRemains(bool secondAdminFirst)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var second = await CreateTargetAsync(test, admin: true);
        var first = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var winner = secondAdminFirst ? second : first;
        var loser = secondAdminFirst ? first : second;
        var saveGate = new PendingDisableGate();
        var attempt = new AdministrationAttempt();
        await using var winnerContext = Context(test, saveGate);
        await using var loserContext = Context(test, attempt);
        await using var services = test.CreateScope();
        var tickets = services.ServiceProvider.GetRequiredService<ISessionTicketStore>();
        var firstService = new PrincipalAdministrationService(winnerContext, test.Clock, tickets);
        var secondService = new PrincipalAdministrationService(loserContext, test.Clock, tickets);

        // Act
        var firstWrite = firstService.DisableAsync(loser.PublicId, Reason(), new AdministrativeActor(Snapshot(winner), test.Clock.Now),
            loser.Version, "first-disable");
        await saveGate.Ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
        var secondWrite = secondService.DisableAsync(winner.PublicId, Reason(), new AdministrativeActor(Snapshot(loser), test.Clock.Now),
            winner.Version, "second-disable");
        try
        {
            await attempt.Started.Task.WaitAsync(TimeSpan.FromSeconds(20));
        }
        finally
        {
            saveGate.Release.TrySetResult();
        }
        var results = await Task.WhenAll(firstWrite, secondWrite);

        // Assert
        Assert.Equal(PrincipalWriteKind.Succeeded, results[0].Kind);
        Assert.Equal(PrincipalWriteKind.Forbidden, results[1].Kind);
        Guid remaining = await test.Database.Context.Principals.Where(value => value.IsEnabled
            && value.RoleAssignments.Any(role => role.Role.Code == "admin")).Select(value => value.PublicId).SingleAsync();
        Assert.Equal(winner.PublicId, remaining);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "principal.disabled");
        Assert.Equal(winner.Id, audit.ActorPrincipalId);
        Assert.Equal(loser.Id, audit.SubjectPrincipalId);
    }

    private static PamDbContext Context(ResourceTestContext test, IInterceptor interceptor) => new(
        new DbContextOptionsBuilder<PamDbContext>().UseNpgsql(test.Database.Context.Database.GetConnectionString())
            .UseSnakeCaseNamingConvention().AddInterceptors(interceptor).Options);

    private static PrincipalSnapshot Snapshot(Principal principal) => new(principal.Id, principal.PublicId,
        principal.DisplayName, principal.Issuer, principal.Subject);

    private static async Task<Principal> CreateTargetAsync(ResourceTestContext test, bool admin = false)
    {
        var target = Principal.CreateMapping("https://identity.example/realms/pam", "bob", "Bob", test.Clock.Now);
        test.Database.Context.Principals.Add(target);
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Principals.Where(value => value.Id == target.Id)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, admin ? ["admin", "user"] : ["user"]);
        return await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == target.Id);
    }

    private static async Task<string> SetVersionAsync(ResourceTestContext test, Guid id)
    {
        using var response = await test.Client.GetAsync($"/api/principals/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(response.Headers.ETag);
        return response.Headers.ETag.Tag;
    }

    private static async Task AssertUnchangedAsync(ResourceTestContext test, long targetId)
    {
        Assert.True(await test.Database.Context.Principals.Where(value => value.Id == targetId).Select(value => value.IsEnabled).SingleAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "principal.disabled"));
    }

    private static ChangePrincipalStatusRequest Reason() => new() { Reason = " Policy review " };

    private sealed class PendingDisableGate : SaveChangesInterceptor
    {
        public TaskCompletionSource Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context?.ChangeTracker.Entries<AuditEvent>().Any(entry => entry.Entity.EventType == "principal.disabled") == true)
            {
                Ready.TrySetResult();
                await Release.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
            }
            return result;
        }
    }

    private sealed class AdministrationAttempt : DbCommandInterceptor
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("FROM pam_roles", StringComparison.Ordinal)
                && command.CommandText.Contains("FOR UPDATE", StringComparison.Ordinal))
            {
                Started.TrySetResult();
            }
            return ValueTask.FromResult(result);
        }
    }
}
