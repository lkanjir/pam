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
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using StackExchange.Redis;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class PrincipalRoleAssignmentTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin")]
    [InlineData("approver")]
    [InlineData("user")]
    public async Task Assign_KnownBundle_AddsOnlyRequestedRoleWithAtomicAuditAndNewPrincipalETag(string roleCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string before = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId, roleCode);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var roles = await response.Content.ReadFromJsonAsync<PrincipalRolesResponse>();
        Assert.NotNull(roles);
        Assert.Equal(target.PublicId, roles.PrincipalId);
        Assert.Equal(roleCode, Assert.Single(roles.Roles));
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(before, response.Headers.ETag.Tag);
        var assignment = await test.Database.Context.PamRoleAssignments.Include(value => value.Role)
            .SingleAsync(value => value.PrincipalId == target.Id);
        Assert.Equal(roleCode, assignment.Role.Code);
        Assert.Equal(test.ActorId, assignment.AssignedByPrincipalId);
        Assert.Equal(test.Clock.Now.UtcDateTime, assignment.AssignedAt);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "role.assigned");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Empty(metadata.RootElement.GetProperty("before").EnumerateArray());
        Assert.Equal(roleCode, Assert.Single(metadata.RootElement.GetProperty("after").EnumerateArray()).GetString());
        Assert.Equal("Reviewed role", metadata.RootElement.GetProperty("reason").GetString());
        using var principal = await test.Client.GetAsync($"/api/principals/{target.PublicId}");
        Assert.Equal(response.Headers.ETag, principal.Headers.ETag);
    }

    [Fact]
    public async Task Assign_EffectiveGrant_RevokesOldCookieAndAllowsFreshLoginWithExplicitBundle()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        using var old = await LoginAsync(test, target.Id);
        string hash = await test.Database.Context.AuthenticationSessionLedgers.Where(value => value.PrincipalId == target.Id)
            .Select(value => value.SessionIdHash).SingleAsync();
        using var before = await old.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, before.StatusCode);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var granted = await AssignAsync(test, target.PublicId, "user");
        await using var scope = test.CreateScope();
        var observation = await scope.ServiceProvider.GetRequiredService<ISessionTicketStore>().ObserveAsync(hash);
        using var oldCookie = await old.GetAsync("/api/me");
        using var fresh = await LoginAsync(test, target.Id);
        using var ownRequests = await fresh.GetAsync("/api/access-requests/mine");

        // Assert
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        Assert.False(observation.HasTicket);
        Assert.NotNull(observation.PendingEnd);
        Assert.Equal("access_changed", observation.PendingEnd.Reason);
        Assert.Equal(HttpStatusCode.Unauthorized, oldCookie.StatusCode);
        Assert.Equal(HttpStatusCode.OK, ownRequests.StatusCode);
    }

    [Fact]
    public async Task Assign_AlreadyAssignedRetry_PreservesFreshSessionsAndDoesNotDuplicateAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var first = await AssignAsync(test, target.PublicId, "user");
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        using var fresh = await LoginAsync(test, target.Id);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var retry = await AssignAsync(test, target.PublicId, "user");
        using var profile = await fresh.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.OK, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "role.assigned"));
        Assert.Equal(1, await test.Database.Context.PamRoleAssignments.CountAsync(value => value.PrincipalId == target.Id));
    }

    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("superadmin", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task Assign_WithoutPermissionOrRecentAuthentication_DoesNotGrant(string role, bool login,
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
        using var response = await AssignAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertNoGrantAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task Assign_WithoutCurrentPrincipalVersion_DoesNotGrant(string? version, int status)
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
        using var response = await AssignAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertNoGrantAsync(test, target.Id);
    }

    [Theory]
    [InlineData("Admin")]
    [InlineData("superadmin")]
    [InlineData("user,admin")]
    public async Task Assign_UnknownOrNonCanonicalCode_DoesNotCreateBundle(string roleCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId, roleCode);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(await test.Database.Context.PamRoles.AnyAsync(value => value.Code == roleCode));
        await AssertNoGrantAsync(test, target.Id);
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("approver")]
    public async Task Assign_OwnAccount_RejectsExistingAndNewRole(string roleCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        Guid id = await test.Database.Context.Principals.Where(value => value.Id == test.ActorId).Select(value => value.PublicId).SingleAsync();
        await SetVersionAsync(test, id);

        // Act
        using var response = await AssignAsync(test, id, roleCode);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("self_change_forbidden", json.RootElement.GetProperty("code").GetString());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "role.assigned"));
    }

    [Fact]
    public async Task Assign_DisabledTarget_RequiresExplicitEnableFirst()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test, enabled: false);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId, "admin");

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("target_disabled", json.RootElement.GetProperty("code").GetString());
        await AssertNoGrantAsync(test, target.Id);
    }

    [Fact]
    public async Task Assign_AuditRejected_RollsBackAssignmentDescriptorAndPrincipalETag()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync("ALTER TABLE audit_events ADD CONSTRAINT reject_role CHECK (event_type <> 'role.assigned')");

        // Act
        using var response = await AssignAsync(test, target.PublicId, "approver");

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await AssertNoGrantAsync(test, target.Id);
        Assert.False(await test.Database.Context.PamRoles.AnyAsync(value => value.Code == "approver"));
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("identity", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task Assign_DirectCaller_RechecksCurrentAuthorityBeforeSessionCleanup(string fault, PrincipalWriteKind expected)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var principal = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var snapshot = new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject);
        if (fault == "role")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == principal.Id).ExecuteDeleteAsync();
        }
        if (fault == "disabled")
        {
            await test.Database.Context.Principals.Where(value => value.Id == principal.Id).ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, false));
        }
        if (fault == "identity")
        {
            snapshot = snapshot with { PublicId = Guid.NewGuid() };
        }
        test.Database.Context.AuthenticationSessionLedgers.Add(new AuthenticationSessionLedger
        {
            PrincipalId = target.Id,
            SessionIdHash = SessionIdentifier.Hash(Guid.NewGuid().ToString("N")),
            CreatedAt = test.Clock.Now.UtcDateTime,
            ExpectedExpiresAt = test.Clock.Now.AddMinutes(30).UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
        var tickets = A.Fake<ISessionTicketStore>();
        var service = new PrincipalRoleService(test.Database.Context, test.Clock, tickets);
        var actor = new AdministrativeActor(snapshot, fault == "freshness" ? test.Clock.Now.AddMinutes(-11) : test.Clock.Now);
        var request = fault == "reason" ? new ChangePrincipalRoleRequest() : Reason();

        // Act
        var result = await service.AssignAsync(target.PublicId, "user", request, actor, target.Version, "direct-role");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Roles);
        A.CallTo(() => tickets.ObserveAsync(A<string>._)).MustNotHaveHappened();
        await AssertNoGrantAsync(test, target.Id);
    }

    [Fact]
    public async Task Assign_RedisUnavailable_LeavesRolelessAccountAndPrincipalVersionUnchanged()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var principal = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var actor = new AdministrativeActor(new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName,
            principal.Issuer, principal.Subject), test.Clock.Now);
        test.Database.Context.AuthenticationSessionLedgers.Add(new AuthenticationSessionLedger
        {
            PrincipalId = target.Id,
            SessionIdHash = SessionIdentifier.Hash(Guid.NewGuid().ToString("N")),
            CreatedAt = test.Clock.Now.UtcDateTime,
            ExpectedExpiresAt = test.Clock.Now.AddMinutes(30).UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
        var tickets = A.Fake<ISessionTicketStore>();
        A.CallTo(() => tickets.ObserveAsync(A<string>._))
            .ThrowsAsync(new RedisConnectionException(ConnectionFailureType.UnableToConnect, CommandFlags.None, "unavailable"));
        var service = new PrincipalRoleService(test.Database.Context, test.Clock, tickets);

        // Act / Assert
        await Assert.ThrowsAsync<RedisConnectionException>(() => service.AssignAsync(target.PublicId, "user", Reason(), actor,
            target.Version, "role-outage"));
        await AssertNoGrantAsync(test, target.Id);
        var unchanged = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == target.Id);
        Assert.True(unchanged.IsEnabled);
        Assert.Equal(target.Version, unchanged.Version);
    }

    [Theory]
    [InlineData(200, 200)]
    [InlineData(201, 409)]
    public async Task Assign_CleanupBatchBoundary_GrantsOnlyAfterCompleteCleanup(int count, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        for (int index = 0; index < count; index++)
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
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId, "user");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200)
        {
            var granted = await response.Content.ReadFromJsonAsync<PrincipalRolesResponse>();
            Assert.NotNull(granted);
            Assert.Equal("user", Assert.Single(granted.Roles));
            Assert.NotEqual(etag, await SetVersionAsync(test, target.PublicId));
        }
        else
        {
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            Assert.Equal("session_cleanup_pending", json.RootElement.GetProperty("code").GetString());
            Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
            await AssertNoGrantAsync(test, target.Id);
        }
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task Assign_InvalidHttpBoundary_DoesNotGrant(string fault)
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
        using var response = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/roles/user", request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoGrantAsync(test, target.Id);
    }

    [Fact]
    public async Task Assign_UnknownPrincipal_ReturnsNotFound()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, Guid.NewGuid(), "user");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertNoGrantAsync(test, target.Id);
    }

    [Fact]
    public async Task Assign_OpenApi_RequiresPrincipalVersionAndDocumentsSecurityErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/roles/{roleCode}").GetProperty("put");
        Assert.Equal("Principal.Roles.Assign", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(), value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("409", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
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

    private static Task<HttpResponseMessage> AssignAsync(ResourceTestContext test, Guid id, string roleCode) =>
        test.Client.PutAsJsonAsync($"/api/principals/{id}/roles/{roleCode}", Reason());

    private static ChangePrincipalRoleRequest Reason() => new() { Reason = " Reviewed role " };

    private static async Task AssertNoGrantAsync(ResourceTestContext test, long targetId)
    {
        Assert.False(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == targetId));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "role.assigned"));
    }
}
