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
public sealed class ApprovalAuthorityAssignmentTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("superadmin", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task AssignAuthority_WithoutPermissionOrRecentAuthentication_DoesNotGrant(string role, bool login,
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
        await AssertNoAuthorityAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task AssignAuthority_WithoutCurrentPrincipalVersion_DoesNotGrant(string? version, int status)
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
        await AssertNoAuthorityAsync(test, target.Id);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("identity", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task AssignAuthority_DirectCaller_RechecksCurrentAuthorityBeforeChangingAssignments(string fault, PrincipalWriteKind expected)
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
        IApprovalAuthorityService service = new ResourceAccessService(test.Database.Context, test.Clock);
        var actor = new AdministrativeActor(snapshot, fault == "freshness" ? test.Clock.Now.AddMinutes(-11) : test.Clock.Now);
        var request = fault == "reason" ? new ChangeResourceAccessRequest() : Reason();

        // Act
        var result = await service.AssignAsync(target.PublicId, test.Resource.PublicId, request, actor, target.Version, "direct-view");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Version);
        await AssertNoAuthorityAsync(test, target.Id);
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task AssignAuthority_InvalidHttpBoundary_DoesNotGrant(string fault)
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
        await AssertNoAuthorityAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignAuthority_UnknownPrincipal_ReturnsNotFound()
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
        await AssertNoAuthorityAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignAuthority_OpenApi_RequiresPrincipalVersionAndDocumentsSecurityErrors()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/approval-authority/{resourceId}").GetProperty("put");
        Assert.Equal("Principal.ApprovalAuthority.Assign", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(), value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("409", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
    }

    [Fact]
    public async Task AssignAuthority_EnabledApprover_GainsOnlyResourceContextWithAtomicAudit()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        using var approver = await LoginAsync(test, target.Id);
        using var before = await approver.GetAsync(test.ResourceUrl);
        Assert.Equal(HttpStatusCode.NotFound, before.StatusCode);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);
        using var detail = await approver.GetAsync(test.ResourceUrl);
        var visible = await approver.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources/visible");
        using var requestable = await approver.GetAsync("/api/resources?requestable=true");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(etag, response.Headers.ETag.Tag);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.NotNull(visible);
        var resource = Assert.Single(visible.Items);
        Assert.Equal(test.Resource.PublicId, resource.Id);
        Assert.Null(resource.Entitlements);
        Assert.Equal(HttpStatusCode.Forbidden, requestable.StatusCode);
        var binding = await test.Database.Context.ResourcePrincipalBindings.AsNoTracking().SingleAsync();
        Assert.Equal(ResourceBindingKind.ApproveRequests, binding.Kind);
        Assert.Equal(target.Id, binding.PrincipalId);
        Assert.Equal(test.Resource.Id, binding.ResourceId);
        Assert.True(binding.IsActive);
        Assert.Equal(test.ActorId, binding.AssignedByPrincipalId);
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync());
        Assert.Equal("approver", await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).Select(value => value.Role.Code).SingleAsync());
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "approval_authority.granted");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(binding.PublicId, metadata.RootElement.GetProperty("bindingId").GetGuid());
        Assert.False(metadata.RootElement.GetProperty("before").GetBoolean());
        Assert.True(metadata.RootElement.GetProperty("after").GetBoolean());
        Assert.Equal("Reviewed authority", metadata.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task AssignAuthority_CombinedUserApprover_StillNeedsIndependentRequesterView()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user");
        var entitlement = new Entitlement
        {
            ResourceId = test.Resource.Id,
            Code = "read",
            Name = "Read",
            IsActive = true,
            MaxDurationMinutes = 60,
            RequiresApproval = true
        };
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        { PrincipalId = target.Id, Entitlement = entitlement, IsEnabled = true, CreatedAt = test.Clock.Now.UtcDateTime });
        await test.Database.Context.SaveChangesAsync();
        using var requester = await LoginAsync(test, target.Id);
        using var csrf = await requester.GetAsync("/api/auth/antiforgery");
        SessionTestHost.UpdateCookie(requester, csrf);
        var tokens = await csrf.Content.ReadFromJsonAsync<Api.Authentication.AntiforgeryTokenResponse>();
        Assert.NotNull(tokens);
        requester.DefaultRequestHeaders.Add("X-CSRF-TOKEN", tokens.RequestToken);
        requester.DefaultRequestHeaders.Add("Idempotency-Key", "requires-view");
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var authority = await AssignAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.NoContent, authority.StatusCode);
        var request = new
        {
            resourceId = test.Resource.PublicId,
            entitlementId = entitlement.PublicId,
            requestedDurationMinutes = 30,
            justification = "Deploy release"
        };
        using var context = await requester.GetAsync(test.ResourceUrl);
        Assert.Equal(HttpStatusCode.OK, context.StatusCode);
        var before = await requester.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources?requestable=true");
        Assert.NotNull(before);
        Assert.Empty(before.Items);
        using var hidden = await requester.PostAsJsonAsync("/api/access-requests", request);
        Assert.Equal(HttpStatusCode.NotFound, hidden.StatusCode);
        Assert.False(await test.Database.Context.AccessRequests.AnyAsync());
        await SetVersionAsync(test, target.PublicId);
        using var view = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/resource-access/{test.Resource.PublicId}",
            new ChangeResourceAccessRequest { Reason = "Add independent requester view" });
        Assert.Equal(HttpStatusCode.NoContent, view.StatusCode);

        // Act
        using var created = await requester.PostAsJsonAsync("/api/access-requests", request);

        // Assert
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var result = await created.Content.ReadFromJsonAsync<Application.AccessRequests.AccessRequestResponse>();
        Assert.NotNull(result);
        Assert.Equal("PendingApproval", result.State);
        Assert.Equal(2, await test.Database.Context.ResourcePrincipalBindings.CountAsync(value => value.PrincipalId == target.Id));
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("inactive")]
    [InlineData("active")]
    public async Task AssignAuthority_OwnAuthority_IsForbiddenEvenForDesiredStateRetry(string state)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["admin", "approver"]);
        var actor = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        if (state != "absent")
        {
            AddAuthority(test, actor.Id, active: state == "active");
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, actor.PublicId);

        // Act
        using var response = await AssignAsync(test, actor.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("self_change_forbidden", body.RootElement.GetProperty("code").GetString());
        Assert.Equal(etag, await SetVersionAsync(test, actor.PublicId));
        Assert.Equal(state == "active", await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.IsActive));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "approval_authority.granted"));
    }

    [Theory]
    [InlineData("disabled", "target_disabled")]
    [InlineData("user", "target_missing_capability")]
    [InlineData("admin", "target_missing_capability")]
    public async Task AssignAuthority_TargetWithoutEnabledApproverSupport_DoesNotGrant(string fault, string code)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test, enabled: fault != "disabled");
        if (fault != "disabled")
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).ExecuteDeleteAsync();
            await SessionTestHost.AssignRolesAsync(test.Database, target.Id, fault);
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(code, body.RootElement.GetProperty("code").GetString());
        await AssertNoAuthorityAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignAuthority_CurrentVersionRetry_IsNoOpAndOldVersionFails()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var first = await AssignAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        using var stale = await AssignAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var retry = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(1, await test.Database.Context.ResourcePrincipalBindings.CountAsync());
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "approval_authority.granted"));
    }

    [Fact]
    public async Task AssignAuthority_InactiveRelationship_ReusesIdentityAndUpdatesVersion()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var original = AddAuthority(test, target.Id, active: false);
        await test.Database.Context.SaveChangesAsync();
        uint version = original.Version;
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var updated = await test.Database.Context.ResourcePrincipalBindings.AsNoTracking().SingleAsync();
        Assert.Equal(original.PublicId, updated.PublicId);
        Assert.True(updated.IsActive);
        Assert.NotEqual(version, updated.Version);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssignAuthority_AuditRejected_RollsBackNewOrRetainedRelationshipAndParentVersion(bool retained)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        if (retained)
        {
            AddAuthority(test, target.Id, active: false);
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_authority_grant CHECK (event_type <> 'approval_authority.granted')");

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.IsActive));
        Assert.Equal(retained ? 1 : 0, await test.Database.Context.ResourcePrincipalBindings.CountAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "approval_authority.granted"));
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("retired")]
    public async Task AssignAuthority_UnavailableResource_DoesNotGrant(string state)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        if (state == "retired")
        {
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        Guid resourceId = state == "missing" ? Guid.NewGuid() : test.Resource.PublicId;

        // Act
        using var response = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/approval-authority/{resourceId}", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.IgnoreQueryFilters().AnyAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "approval_authority.granted"));
    }

    [Fact]
    public async Task Read_UnsupportedAuthorityInDatabase_DoesNotGrantUserApprovalContext()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        AddAuthority(test, test.ActorId);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl);
        var page = await test.Client.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources/visible");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.NotNull(page);
        Assert.Empty(page.Items);
    }

    [Fact]
    public async Task Remove_ApproverRole_DeactivatesAuthorityAndRegrantDoesNotRestoreIt()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user");
        var authority = AddAuthority(test, target.Id);
        var view = test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var message = new HttpRequestMessage(HttpMethod.Delete, $"/api/principals/{target.PublicId}/roles/approver")
        { Content = JsonContent.Create(new ChangePrincipalRoleRequest { Reason = "Remove approver capability" }) };
        using var removed = await test.Client.SendAsync(message);
        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var granted = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/roles/approver",
            new ChangePrincipalRoleRequest { Reason = "Restore role only" });

        // Assert
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.Where(value => value.Id == authority.Id).Select(value => value.IsActive).SingleAsync());
        Assert.True(await test.Database.Context.ResourcePrincipalBindings.Where(value => value.Id == view.Id).Select(value => value.IsActive).SingleAsync());
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "approval_authority.deactivated");
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal("supporting_role_removed", audit.ReasonCode);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(authority.PublicId, metadata.RootElement.GetProperty("bindingId").GetGuid());
    }

    [Fact]
    public async Task Remove_RequiredAuthorityDeactivationAuditFails_RollsBackRoleAndScope()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await TargetAsync(test);
        var authority = AddAuthority(test, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_authority_deactivation CHECK (event_type <> 'approval_authority.deactivated')");
        using var message = new HttpRequestMessage(HttpMethod.Delete, $"/api/principals/{target.PublicId}/roles/approver")
        { Content = JsonContent.Create(new ChangePrincipalRoleRequest { Reason = "Must stay atomic" }) };

        // Act
        using var response = await test.Client.SendAsync(message);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == target.Id && value.Role.Code == "approver"));
        Assert.True(await test.Database.Context.ResourcePrincipalBindings.Where(value => value.Id == authority.Id).Select(value => value.IsActive).SingleAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "role.removed"));
    }

    private static ResourcePrincipalBinding AddAuthority(ResourceTestContext test, long principalId, bool active = true)
    {
        var binding = new ResourcePrincipalBinding
        {
            PrincipalId = principalId,
            ResourceId = test.Resource.Id,
            Kind = ResourceBindingKind.ApproveRequests,
            IsActive = active,
            AssignedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            AssignedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        };
        test.Database.Context.ResourcePrincipalBindings.Add(binding);
        return binding;
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
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "approver");
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
        using var response = await test.Client.GetAsync($"/api/principals/{id}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(response.Headers.ETag);
        return response.Headers.ETag.Tag;
    }

    private static string Url(ResourceTestContext test, Guid id) =>
        $"/api/principals/{id}/approval-authority/{test.Resource.PublicId}";

    private static Task<HttpResponseMessage> AssignAsync(ResourceTestContext test, Guid id) =>
        test.Client.PutAsJsonAsync(Url(test, id), Reason());

    private static ChangeResourceAccessRequest Reason() => new() { Reason = " Reviewed authority " };

    private static async Task AssertNoAuthorityAsync(ResourceTestContext test, long targetId)
    {
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.PrincipalId == targetId));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "approval_authority.granted"));
    }
}
