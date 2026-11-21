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
using FakeItEasy;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection2.Name)]
public sealed class PrincipalRoleRemovalTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("superadmin", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task Remove_WithoutPermissionOrRecentAuthentication_PreservesAssignment(string role, bool login,
        bool timestamp, int age, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: role.Length == 0 ? [] : [role]);
        var target = await TargetAsync(test);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: timestamp);
        }
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task Remove_WithoutCurrentPrincipalVersion_PreservesAssignment(string? version, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        if (version is not null)
        {
            test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", version);
        }

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("superadmin")]
    [InlineData("user,admin")]
    public async Task Remove_UnknownOrNonCanonicalCode_PreservesKnownAssignment(string roleCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RemoveAsync(test, target.PublicId, roleCode);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await test.Database.Context.PamRoles.AnyAsync(value => value.Code == roleCode));
        await AssertUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("approver")]
    public async Task Remove_OwnAccount_RejectsExistingAndNewRole(string roleCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid id = await test.Database.Context.Principals.Where(value => value.Id == test.ActorId).Select(value => value.PublicId).SingleAsync();
        await SetVersionAsync(test, id);

        // Act
        using var response = await RemoveAsync(test, id, roleCode);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("self_change_forbidden", json.RootElement.GetProperty("code").GetString());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "role.removed"));
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task Remove_InvalidHttpBoundary_PreservesAssignment(string fault)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        if (fault == "csrf")
        {
            test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        }
        var request = new ChangePrincipalRoleRequest
        {
            Reason = fault switch { "empty-reason" => string.Empty, "long-reason" => new string('x', 501), _ => "Review" }
        };

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "user", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Fact]
    public async Task Remove_UnknownPrincipal_ReturnsNotFound()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RemoveAsync(test, Guid.NewGuid(), "user");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
    }

    [Fact]
    public async Task Remove_OpenApi_RequiresPrincipalVersionAndDocumentsSecurityErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/roles/{roleCode}").GetProperty("delete");
        Assert.Equal("Principal.Roles.Remove", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(), value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("409", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
    }

    [Fact]
    public async Task Remove_UserBundle_DeactivatesOnlyItsEnabledEligibilityWithExactRelationshipAudits()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var first = AddEligibility(test, target.Id, "first", true);
        var second = AddEligibility(test, target.Id, "second", true);
        var alreadyDisabled = AddEligibility(test, target.Id, "disabled", false);
        var foreign = AddEligibility(test, test.ActorId, "foreign", true);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var roles = await response.Content.ReadFromJsonAsync<PrincipalRolesResponse>();
        Assert.NotNull(roles);
        Assert.Equal("approver", Assert.Single(roles.Roles));
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(etag, response.Headers.ETag.Tag);
        var rules = await test.Database.Context.EligibilityRules.AsNoTracking().ToDictionaryAsync(value => value.Id);
        Assert.False(rules[first.Id].IsEnabled);
        Assert.False(rules[second.Id].IsEnabled);
        Assert.False(rules[alreadyDisabled.Id].IsEnabled);
        Assert.True(rules[foreign.Id].IsEnabled);
        var changes = await test.Database.Context.AuditEvents.Where(value => value.EventType == "eligibility.deactivated")
            .AsNoTracking().ToListAsync();
        Assert.Equal(2, changes.Count);
        var expectedIds = new[] { first.PublicId, second.PublicId }.Order().ToArray();
        var auditedIds = new List<Guid>();
        foreach (var audit in changes)
        {
            Assert.Equal(test.ActorId, audit.ActorPrincipalId);
            Assert.Equal(target.Id, audit.SubjectPrincipalId);
            Assert.Equal(test.Resource.Id, audit.ResourceId);
            Assert.Contains(audit.EntitlementId, new long?[] { first.EntitlementId, second.EntitlementId });
            Assert.Equal("supporting_role_removed", audit.ReasonCode);
            Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
            Assert.NotNull(audit.Metadata);
            using var metadata = JsonDocument.Parse(audit.Metadata);
            auditedIds.Add(metadata.RootElement.GetProperty("eligibilityId").GetGuid());
            Assert.True(metadata.RootElement.GetProperty("before").GetBoolean());
            Assert.False(metadata.RootElement.GetProperty("after").GetBoolean());
            Assert.Equal("Reviewed role", metadata.RootElement.GetProperty("reason").GetString());
        }
        Assert.Equal(expectedIds, auditedIds.Order());
        var roleAudit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "role.removed");
        Assert.NotNull(roleAudit.Metadata);
        using var roleMetadata = JsonDocument.Parse(roleAudit.Metadata);
        Assert.Equal(2, roleMetadata.RootElement.GetProperty("before").GetArrayLength());
        Assert.Equal("approver", Assert.Single(roleMetadata.RootElement.GetProperty("after").EnumerateArray()).GetString());
    }

    [Fact]
    public async Task Remove_ApproverBundle_PreservesRequesterEligibility()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var eligibility = AddEligibility(test, target.Id, "retain", true);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "approver");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var roles = await response.Content.ReadFromJsonAsync<PrincipalRolesResponse>();
        Assert.NotNull(roles);
        Assert.Equal("user", Assert.Single(roles.Roles));
        Assert.True(await test.Database.Context.EligibilityRules.Where(value => value.Id == eligibility.Id).Select(value => value.IsEnabled).SingleAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "eligibility.deactivated"));
    }

    [Theory]
    [InlineData("role.removed")]
    [InlineData("eligibility.deactivated")]
    public async Task Remove_AnyRequiredAuditRejected_RollsBackRoleEligibilityAndPrincipalVersion(string rejected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var eligibility = AddEligibility(test, target.Id, "atomic", true);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        string constraint = rejected == "role.removed"
            ? "ALTER TABLE audit_events ADD CONSTRAINT reject_remove CHECK (event_type <> 'role.removed')"
            : "ALTER TABLE audit_events ADD CONSTRAINT reject_remove CHECK (event_type <> 'eligibility.deactivated')";
        await test.Database.Context.Database.ExecuteSqlRawAsync(constraint);

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await AssertUnchangedAsync(test, target.Id);
        Assert.True(await test.Database.Context.EligibilityRules.Where(value => value.Id == eligibility.Id).Select(value => value.IsEnabled).SingleAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "eligibility.deactivated"));
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
    }

    [Fact]
    public async Task Remove_AbsentRoleRetry_DoesNotChangeVersionOrDuplicateAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var first = await RemoveAsync(test, target.PublicId, "user");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var retry = await RemoveAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "role.removed"));
    }

    [Fact]
    public async Task Remove_DisabledAccount_StillReducesPrivileges()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test, enabled: false);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RemoveAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(await test.Database.Context.Principals.Where(value => value.Id == target.Id).Select(value => value.IsEnabled).SingleAsync());
        Assert.False(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == target.Id && value.Role.Code == "user"));
    }

    [Fact]
    public async Task Remove_ThenRegrant_DoesNotReviveUnusedCookieOrEligibility()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var eligibility = AddEligibility(test, target.Id, "never-restore", true);
        await test.Database.Context.SaveChangesAsync();
        using var old = await LoginAsync(test, target.Id);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var removed = await RemoveAsync(test, target.PublicId, "user");
        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        await SetVersionAsync(test, target.PublicId);
        using var restored = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/roles/user", Reason());
        Assert.Equal(HttpStatusCode.OK, restored.StatusCode);

        // Act
        using var replay = await old.GetAsync("/api/me");
        using var fresh = await LoginAsync(test, target.Id);
        using var history = await fresh.GetAsync("/api/access-requests/mine");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
        Assert.Equal(HttpStatusCode.OK, history.StatusCode);
        Assert.False(await test.Database.Context.EligibilityRules.Where(value => value.Id == eligibility.Id).Select(value => value.IsEnabled).SingleAsync());
    }

    [Fact]
    public async Task Remove_ManySessionsAndUnavailableRedis_DoesNotDelayPrivilegeReduction()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        for (int index = 0; index < 201; index++)
        {
            test.Database.Context.AuthenticationSessionLedgers.Add(new AuthenticationSessionLedger
            {
                PrincipalId = target.Id,
                SessionIdHash = SessionIdentifier.Hash(Guid.NewGuid().ToString("N")),
                CreatedAt = test.Clock.Now.UtcDateTime,
                ExpectedExpiresAt = test.Clock.Now.AddMinutes(30).UtcDateTime
            });
        }
        await test.Database.Context.SaveChangesAsync();
        var principal = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var actor = new AdministrativeActor(Snapshot(principal), test.Clock.Now);
        var tickets = A.Fake<ISessionTicketStore>();
        A.CallTo(() => tickets.ObserveAsync(A<string>._)).ThrowsAsync(new InvalidOperationException("Unavailable"));
        var service = new PrincipalRoleService(test.Database.Context, test.Clock, tickets);

        // Act
        var result = await service.RemoveAsync(target.PublicId, "user", Reason(), actor, target.Version, "remove-no-redis");

        // Assert
        Assert.Equal(PrincipalWriteKind.Succeeded, result.Kind);
        Assert.False(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == target.Id && value.Role.Code == "user"));
        A.CallTo(() => tickets.ObserveAsync(A<string>._)).MustNotHaveHappened();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Remove_TwoAdminsCrossRemoving_OnlyFirstCommitsAndOneAdminRemains(bool secondFirst)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var second = await TargetAsync(test);
        await SessionTestHost.AssignRolesAsync(test.Database, second.Id, "admin");
        var first = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var winner = secondFirst ? second : first;
        var loser = secondFirst ? first : second;
        var saveGate = new PendingRemovalGate();
        var attempt = new AdministrationAttempt();
        await using var winnerContext = Context(test, saveGate);
        await using var loserContext = Context(test, attempt);
        var tickets = A.Fake<ISessionTicketStore>();
        var firstService = new PrincipalRoleService(winnerContext, test.Clock, tickets);
        var secondService = new PrincipalRoleService(loserContext, test.Clock, tickets);

        // Act
        var firstWrite = firstService.RemoveAsync(loser.PublicId, "admin", Reason(), new AdministrativeActor(Snapshot(winner), test.Clock.Now),
            loser.Version, "first-remove");
        await saveGate.Ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
        var secondWrite = secondService.RemoveAsync(winner.PublicId, "admin", Reason(), new AdministrativeActor(Snapshot(loser), test.Clock.Now),
            winner.Version, "second-remove");
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
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "role.removed");
        Assert.Equal(winner.Id, audit.ActorPrincipalId);
        Assert.Equal(loser.Id, audit.SubjectPrincipalId);
    }

    private static EligibilityRule AddEligibility(ResourceTestContext test, long principalId, string code, bool enabled)
    {
        var rule = new EligibilityRule
        {
            PrincipalId = principalId,
            IsEnabled = enabled,
            Entitlement = new Entitlement
            {
                ResourceId = test.Resource.Id,
                Code = code,
                Name = code,
                IsActive = true,
                RequiresApproval = true,
                MaxDurationMinutes = 60
            }
        };
        test.Database.Context.EligibilityRules.Add(rule);
        return rule;
    }

    private static PamDbContext Context(ResourceTestContext test, IInterceptor interceptor) => new(
        new DbContextOptionsBuilder<PamDbContext>().UseNpgsql(test.Database.Context.Database.GetConnectionString())
            .UseSnakeCaseNamingConvention().AddInterceptors(interceptor).Options);

    private static PrincipalSnapshot Snapshot(Principal principal) => new(principal.Id, principal.PublicId,
        principal.DisplayName, principal.Issuer, principal.Subject);

    private sealed class PendingRemovalGate : SaveChangesInterceptor
    {
        public TaskCompletionSource Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (eventData.Context?.ChangeTracker.Entries<AuditEvent>().Any(entry => entry.Entity.EventType == "role.removed") == true)
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

    private static async Task<Principal> TargetAsync(ResourceTestContext test, bool enabled = true)
    {
        var target = Principal.CreateMapping("https://identity.example/realms/pam", "bob", "Bob", test.Clock.Now);
        test.Database.Context.Principals.Add(target);
        await test.Database.Context.SaveChangesAsync();
        if (enabled)
        {
            await test.Database.Context.Principals.Where(value => value.Id == target.Id).ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        }
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user", "approver");
        return await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == target.Id);
    }

    private static async Task<HttpClient> LoginAsync(ResourceTestContext test, long id)
    {
        var client = test.CreateClient();
        using var login = await client.GetAsync("/login?principal-id=" + id.ToString(CultureInfo.InvariantCulture));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        SessionTestHost.UpdateCookie(client, login);
        return client;
    }

    private static async Task<string> SetVersionAsync(ResourceTestContext test, Guid id)
    {
        using var response = await test.Client.GetAsync($"/api/principals/{id}/roles");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(response.Headers.ETag);
        return response.Headers.ETag.Tag;
    }

    private static async Task<HttpResponseMessage> RemoveAsync(ResourceTestContext test, Guid id, string roleCode,
        ChangePrincipalRoleRequest? request = null)
    {
        using var message = new HttpRequestMessage(HttpMethod.Delete, $"/api/principals/{id}/roles/{roleCode}")
        { Content = JsonContent.Create(request ?? Reason()) };
        return await test.Client.SendAsync(message);
    }

    private static ChangePrincipalRoleRequest Reason() => new() { Reason = " Reviewed role " };

    private static async Task AssertUnchangedAsync(ResourceTestContext test, long targetId)
    {
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == targetId && value.Role.Code == "user"));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "role.removed"));
    }
}
