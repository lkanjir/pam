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
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection4.Name)]
public sealed class PrincipalEnableTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Enable_DisabledMapping_RestoresRetainedRolesWithAtomicAuditAndNewVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await EnableAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var principal = await response.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(principal);
        Assert.True(principal.IsEnabled);
        Assert.Equal(target.PublicId, principal.Id);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(etag, response.Headers.ETag.Tag);
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(role => role.PrincipalId == target.Id && role.Role.Code == "user"));
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "principal.enabled");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.False(metadata.RootElement.GetProperty("before").GetProperty("isEnabled").GetBoolean());
        Assert.True(metadata.RootElement.GetProperty("after").GetProperty("isEnabled").GetBoolean());
        Assert.Equal("Reviewed retained assignments", metadata.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Enable_PreviouslyDisabledAccount_RejectsUnusedOldCookieAndAcceptsNewLogin()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test, enabled: true);
        using var original = await LoginTargetAsync(test, target.Id);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var disable = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());
        Assert.Equal(HttpStatusCode.OK, disable.StatusCode);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var enabled = await EnableAsync(test, target.PublicId);
        using var oldCookie = await original.GetAsync("/api/me");
        using var fresh = await LoginTargetAsync(test, target.Id);
        using var newCookie = await fresh.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, oldCookie.StatusCode);
        Assert.Equal(HttpStatusCode.OK, newCookie.StatusCode);
        var sessions = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking()
            .Where(value => value.PrincipalId == target.Id).OrderBy(value => value.Id).ToListAsync();
        Assert.Equal(2, sessions.Count);
        await using var scope = test.CreateScope();
        var state = await scope.ServiceProvider.GetRequiredService<ISessionTicketStore>().ObserveAsync(sessions[0].SessionIdHash);
        Assert.False(state.HasTicket);
        Assert.Null(sessions[1].EndedAt);
    }

    [Fact]
    public async Task Enable_AlreadyEnabledRetry_PreservesNewSessionsAndDoesNotDuplicateAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var first = await EnableAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var fresh = await LoginTargetAsync(test, target.Id);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var retry = await EnableAsync(test, target.PublicId);
        using var profile = await fresh.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "principal.enabled"));
    }

    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task Enable_WithoutCurrentPermissionOrFreshSession_LeavesAccountDisabled(string role, bool login,
        bool timestamp, int age, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: role.Length == 0 ? [] : [role]);
        var target = await TargetAsync(test);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: timestamp);
        }
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await EnableAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertDisabledAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task Enable_MissingInvalidOrStaleVersion_LeavesAccountDisabled(string? tag, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        if (tag is not null)
        {
            test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", tag);
        }

        // Act
        using var response = await EnableAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertDisabledAsync(test, target.Id);
    }

    [Fact]
    public async Task Enable_OwnAlreadyEnabledAccount_CannotBypassSelfRestrictionThroughNoOp()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid id = await test.Database.Context.Principals.Where(value => value.Id == test.ActorId).Select(value => value.PublicId).SingleAsync();
        await SetVersionAsync(test, id);

        // Act
        using var response = await EnableAsync(test, id);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("self_change_forbidden", json.RootElement.GetProperty("code").GetString());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "principal.enabled"));
    }

    [Fact]
    public async Task Enable_AuditRejected_KeepsAccountDisabledAndRetainsSafeTicketRevocation()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test, enabled: true);
        using var original = await LoginTargetAsync(test, target.Id);
        string hash = await test.Database.Context.AuthenticationSessionLedgers.Where(value => value.PrincipalId == target.Id)
            .Select(value => value.SessionIdHash).SingleAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var disabled = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/disable", Reason());
        Assert.Equal(HttpStatusCode.OK, disabled.StatusCode);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_enable CHECK (event_type <> 'principal.enabled')");

        // Act
        using var response = await EnableAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await AssertDisabledAsync(test, target.Id);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
        await using var scope = test.CreateScope();
        var state = await scope.ServiceProvider.GetRequiredService<ISessionTicketStore>().ObserveAsync(hash);
        Assert.False(state.HasTicket);
        Assert.NotNull(state.PendingEnd);
        Assert.Equal("access_changed", state.PendingEnd.Reason);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Enable_CleanupUnavailableOrSuperseded_DoesNotRestorePrivileges(bool casLost)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        string hash = SessionIdentifier.Hash(Guid.NewGuid().ToString("N"));
        test.Database.Context.AuthenticationSessionLedgers.Add(new AuthenticationSessionLedger
        {
            PrincipalId = target.Id,
            SessionIdHash = hash,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ExpectedExpiresAt = test.Clock.Now.AddMinutes(30).UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
        var principal = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var actor = new AdministrativeActor(new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName,
            principal.Issuer, principal.Subject), test.Clock.Now);
        var tickets = A.Fake<ISessionTicketStore>();
        var observed = new SessionObservation(true, test.Clock.Now.AddMinutes(30), test.Clock.Now.AddMinutes(30), "lease")
        { TicketVersion = "ticket" };
        if (casLost)
        {
            A.CallTo(() => tickets.ObserveAsync(hash)).ReturnsNextFromSequence(
                Task.FromResult(observed), Task.FromResult(observed with { TicketVersion = "renewed-ticket" }));
            A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation>._))
                .Returns(Task.FromResult<PendingSessionEnd?>(null));
        }
        else
        {
            A.CallTo(() => tickets.ObserveAsync(hash))
                .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, CommandFlags.None, "unavailable"));
        }
        var service = new PrincipalAdministrationService(test.Database.Context, test.Clock, tickets);

        // Act / Assert
        if (casLost)
        {
            var result = await service.EnableAsync(target.PublicId, Reason(), actor, target.Version, "enable-cas");
            Assert.Equal(PrincipalWriteKind.SessionCleanupPending, result.Kind);
            Assert.Null(result.Principal);
            A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>.That.Matches(end => end.SessionIdHash == hash), observed))
                .MustHaveHappenedOnceExactly();
        }
        else
        {
            await Assert.ThrowsAsync<RedisConnectionException>(() => service.EnableAsync(target.PublicId, Reason(), actor, target.Version, "enable-outage"));
        }
        await AssertDisabledAsync(test, target.Id);
    }

    [Fact]
    public async Task Enable_MoreThanCleanupBatch_LeavesDisabledUntilReconciliationAdvances()
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
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var pending = await EnableAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.Conflict, pending.StatusCode);
        using var problem = JsonDocument.Parse(await pending.Content.ReadAsStringAsync());
        Assert.Equal("session_cleanup_pending", problem.RootElement.GetProperty("code").GetString());
        await AssertDisabledAsync(test, target.Id);
        await using (var scope = test.CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<SessionReconciler>().RunAsync(new(), 1000);
        }

        // Act
        using var retry = await EnableAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(201, await test.Database.Context.AuthenticationSessionLedgers.CountAsync(value => value.PrincipalId == target.Id && value.EndedAt != null));
        Assert.True(await test.Database.Context.Principals.Where(value => value.Id == target.Id).Select(value => value.IsEnabled).SingleAsync());
    }

    [Fact]
    public async Task Enable_UnknownMapping_ReturnsNotFoundWithoutChangingAnotherAccount()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{Guid.NewGuid()}/enable", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(response.Headers.ETag);
        await AssertDisabledAsync(test, target.Id);
    }

    [Fact]
    public async Task Enable_OpenApi_DeclaresRequiredPrincipalVersionAndSecurityErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/enable").GetProperty("post");
        Assert.Equal("Principal.Enable", operation.GetProperty("operationId").GetString());
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
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task Enable_InvalidRequestBoundary_LeavesTargetDisabled(string fault)
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
        var request = new ChangePrincipalStatusRequest
        {
            Reason = fault switch { "empty-reason" => string.Empty, "long-reason" => new string('x', 501), _ => "Review" }
        };

        // Act
        using var response = await test.Client.PostAsJsonAsync($"/api/principals/{target.PublicId}/enable", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertDisabledAsync(test, target.Id);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("public-id", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task Enable_DirectCaller_RechecksCurrentAuthorityAndValidation(string fault, PrincipalWriteKind expected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var principal = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var snapshot = new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject);
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
        test.Database.Context.AuthenticationSessionLedgers.Add(new AuthenticationSessionLedger
        {
            PrincipalId = target.Id,
            SessionIdHash = SessionIdentifier.Hash(Guid.NewGuid().ToString("N")),
            CreatedAt = test.Clock.Now.UtcDateTime,
            ExpectedExpiresAt = test.Clock.Now.AddMinutes(30).UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
        var tickets = A.Fake<ISessionTicketStore>();
        var service = new PrincipalAdministrationService(test.Database.Context, test.Clock, tickets);
        var request = fault == "reason" ? new ChangePrincipalStatusRequest { Reason = string.Empty } : Reason();

        // Act
        var result = await service.EnableAsync(target.PublicId, request, actor, target.Version, "direct-enable");

        // Assert
        A.CallTo(() => tickets.ObserveAsync(A<string>._)).MustNotHaveHappened();
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Principal);
        await AssertDisabledAsync(test, target.Id);
    }

    private static async Task<Principal> TargetAsync(ResourceTestContext test, bool enabled = false)
    {
        var target = Principal.CreateMapping("https://identity.example/realms/pam", "bob", "Bob", test.Clock.Now);
        test.Database.Context.Principals.Add(target);
        await test.Database.Context.SaveChangesAsync();
        if (enabled)
        {
            await test.Database.Context.Principals.Where(value => value.Id == target.Id)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        }
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user");
        return await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == target.Id);
    }

    private static async Task<HttpClient> LoginTargetAsync(ResourceTestContext test, long id)
    {
        var client = test.CreateClient();
        using var login = await client.GetAsync("/login?principal-id=" + id.ToString(CultureInfo.InvariantCulture));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        SessionTestHost.UpdateCookie(client, login);
        return client;
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

    private static Task<HttpResponseMessage> EnableAsync(ResourceTestContext test, Guid id) =>
        test.Client.PostAsJsonAsync($"/api/principals/{id}/enable", Reason());

    private static ChangePrincipalStatusRequest Reason() => new() { Reason = " Reviewed retained assignments " };

    private static async Task AssertDisabledAsync(ResourceTestContext test, long id)
    {
        Assert.False(await test.Database.Context.Principals.Where(value => value.Id == id).Select(value => value.IsEnabled).SingleAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "principal.enabled"));
    }
}
