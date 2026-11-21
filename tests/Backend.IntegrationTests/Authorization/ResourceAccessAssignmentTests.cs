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
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class ResourceAccessAssignmentTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("superadmin", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task AssignView_WithoutPermissionOrRecentAuthentication_DoesNotGrant(string role, bool login,
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
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertNoViewAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task AssignView_WithoutCurrentPrincipalVersion_DoesNotGrant(string? version, int status)
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
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertNoViewAsync(test, target.Id);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("identity", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task AssignView_DirectCaller_RechecksCurrentAuthorityBeforeChangingAssignments(string fault, PrincipalWriteKind expected)
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
        var service = new ResourceAccessService(test.Database.Context, test.Clock);
        var actor = new AdministrativeActor(snapshot, fault == "freshness" ? test.Clock.Now.AddMinutes(-11) : test.Clock.Now);
        var request = fault == "reason" ? new ChangeResourceAccessRequest() : Reason();

        // Act
        var result = await service.AssignAsync(target.PublicId, test.Resource.PublicId, request, actor, target.Version, "direct-view");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Version);
        await AssertNoViewAsync(test, target.Id);
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task AssignView_InvalidHttpBoundary_DoesNotGrant(string fault)
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
        var request = new ChangeResourceAccessRequest
        {
            Reason = fault switch { "empty-reason" => string.Empty, "long-reason" => new string('x', 501), _ => "Review" }
        };

        // Act
        using var response = await test.Client.PutAsJsonAsync(Url(test, target.PublicId), request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoViewAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignView_UnknownPrincipal_ReturnsNotFound()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, Guid.NewGuid());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertNoViewAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignView_OpenApi_RequiresPrincipalVersionAndDocumentsSecurityErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/resource-access/{resourceId}").GetProperty("put");
        Assert.Equal("Principal.ResourceAccess.Assign", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(), value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("409", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
    }

    [Theory]
    [InlineData("user")]
    [InlineData("approver")]
    public async Task AssignView_EnabledScopedReader_ImmediatelyEnablesReadInRetainedSession(string roleCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        if (roleCode == "approver")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).ExecuteDeleteAsync();
            await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "approver");
        }
        using var reader = await LoginAsync(test, target.Id);
        using var hidden = await reader.GetAsync(test.ResourceUrl);
        Assert.Equal(HttpStatusCode.NotFound, hidden.StatusCode);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);
        using var visible = await reader.GetAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(etag, response.Headers.ETag.Tag);
        Assert.Equal(HttpStatusCode.OK, visible.StatusCode);
        var resource = await visible.Content.ReadFromJsonAsync<Application.Resources.ResourceResponse>();
        Assert.NotNull(resource);
        Assert.Equal(test.Resource.PublicId, resource.Id);
        var binding = await test.Database.Context.ResourcePrincipalBindings.AsNoTracking().SingleAsync(value => value.PrincipalId == target.Id);
        Assert.Equal(ResourceBindingKind.ViewResource, binding.Kind);
        Assert.True(binding.IsActive);
        Assert.Equal(test.ActorId, binding.AssignedByPrincipalId);
        Assert.Equal(test.ActorId, binding.ModifiedByPrincipalId);
        Assert.Equal(test.Clock.Now.UtcDateTime, binding.AssignedAt);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "resource_access.granted");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(binding.PublicId, metadata.RootElement.GetProperty("bindingId").GetGuid());
        Assert.False(metadata.RootElement.GetProperty("before").GetBoolean());
        Assert.True(metadata.RootElement.GetProperty("after").GetBoolean());
        Assert.Equal("Reviewed visibility", metadata.RootElement.GetProperty("reason").GetString());
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync());
        Assert.Equal(roleCode, await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).Select(value => value.Role.Code).SingleAsync());
    }

    [Theory]
    [InlineData("admin,user", 204)]
    [InlineData("admin,approver", 204)]
    [InlineData("admin", 409)]
    public async Task AssignView_OwnAccount_RequiresAnExistingExplicitScopedReadBundle(string roles, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: roles.Split(','));
        var target = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(status == 204, await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.PrincipalId == target.Id && value.IsActive));
        Assert.Equal(roles.Split(',').Order(), await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id)
            .Select(value => value.Role.Code).OrderBy(value => value).ToListAsync());
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync());
    }

    [Fact]
    public async Task AssignView_CurrentVersionRetry_IsNoOpAndStaleRetryCannotBypassVersionCheck()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string original = await SetVersionAsync(test, target.PublicId);
        using var first = await AssignAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        using var stale = await AssignAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        string current = await SetVersionAsync(test, target.PublicId);
        Assert.NotEqual(original, current);

        // Act
        using var retry = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(1, await test.Database.Context.ResourcePrincipalBindings.CountAsync(value => value.PrincipalId == target.Id));
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "resource_access.granted"));
    }

    [Fact]
    public async Task AssignView_InactiveBinding_ReactivatesExistingRelationshipAndUpdatesBothVersions()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var original = test.AddViewBinding(test.Resource, target.Id);
        original.IsActive = false;
        await test.Database.Context.SaveChangesAsync();
        uint bindingVersion = original.Version;
        await test.AuthenticateAsync(includeResourceVersion: false);
        string principalVersion = await SetVersionAsync(test, target.PublicId);
        test.Clock.Now = test.Clock.Now.AddMinutes(1);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var updated = await test.Database.Context.ResourcePrincipalBindings.AsNoTracking().SingleAsync(value => value.PrincipalId == target.Id);
        Assert.Equal(original.PublicId, updated.PublicId);
        Assert.True(updated.IsActive);
        Assert.NotEqual(bindingVersion, updated.Version);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(principalVersion, response.Headers.ETag.Tag);
        Assert.Equal(test.Clock.Now.UtcDateTime, updated.ModifiedAt);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssignView_RequiredAuditRejected_RollsBackNewOrRetainedBindingAndParentVersion(bool retained)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        if (retained)
        {
            test.AddViewBinding(test.Resource, target.Id).IsActive = false;
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_view_grant CHECK (event_type <> 'resource_access.granted')");

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.PrincipalId == target.Id && value.IsActive));
        Assert.Equal(retained ? 1 : 0, await test.Database.Context.ResourcePrincipalBindings.CountAsync(value => value.PrincipalId == target.Id));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "resource_access.granted"));
    }

    [Theory]
    [InlineData("disabled", "target_disabled")]
    [InlineData("missing-capability", "target_missing_capability")]
    public async Task AssignView_InvalidTargetState_DoesNotGrant(string fault, string code)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test, enabled: fault != "disabled");
        if (fault == "missing-capability")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).ExecuteDeleteAsync();
            await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "admin");
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
        await AssertNoViewAsync(test, target.Id);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("retired")]
    public async Task AssignView_UnavailableResource_DoesNotCreateRelationship(string fault)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        if (fault == "retired")
        {
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        Guid resourceId = fault == "missing" ? Guid.NewGuid() : test.Resource.PublicId;

        // Act
        using var response = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/resource-access/{resourceId}", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.IgnoreQueryFilters().AnyAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "resource_access.granted"));
    }

    [Fact]
    public async Task AssignView_ClientSuppliedAuthorityAndPrincipalFields_StoresOnlyViewForRouteTarget()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await test.Client.PutAsJsonAsync(Url(test, target.PublicId), new
        {
            reason = "Explicit route target",
            principalId = test.ActorId,
            kind = "ApproveRequests",
            isActive = false
        });

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var binding = await test.Database.Context.ResourcePrincipalBindings.AsNoTracking().SingleAsync();
        Assert.Equal(target.Id, binding.PrincipalId);
        Assert.Equal(ResourceBindingKind.ViewResource, binding.Kind);
        Assert.True(binding.IsActive);
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync());
        Assert.Equal("user", await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).Select(value => value.Role.Code).SingleAsync());
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
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user");
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
        using var response = await test.Client.GetAsync($"/api/principals/{id}/resource-access");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(response.Headers.ETag);
        return response.Headers.ETag.Tag;
    }

    private static string Url(ResourceTestContext test, Guid id) =>
        $"/api/principals/{id}/resource-access/{test.Resource.PublicId}";

    private static Task<HttpResponseMessage> AssignAsync(ResourceTestContext test, Guid id) =>
        test.Client.PutAsJsonAsync(Url(test, id), Reason());

    private static ChangeResourceAccessRequest Reason() => new() { Reason = " Reviewed visibility " };

    private static async Task AssertNoViewAsync(ResourceTestContext test, long targetId)
    {
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.PrincipalId == targetId));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "resource_access.granted"));
    }
}
