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

[Collection(StorageCollection4.Name)]
public sealed class EligibilityRevocationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("superadmin", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task RevokeEligibility_WithoutPermissionOrRecentAuthentication_DoesNotGrant(string role, bool login,
        bool timestamp, int age, int status)
    {
        // Arrange
        await using var test = await CreateAsync(
            roles: role.Length == 0 ? [] : [role]);
        var target = await TargetAsync(test);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: timestamp);
        }
        test.Clock.Now = test.Clock.Now.AddSeconds(age);

        // Act
        using var response = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertEligibilityUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task RevokeEligibility_WithoutCurrentPrincipalVersion_DoesNotGrant(string? version, int status)
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        if (version is not null)
        {
            test.Client.DefaultRequestHeaders.TryAddWithoutValidation("If-Match", version);
        }

        // Act
        using var response = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertEligibilityUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("identity", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task RevokeEligibility_DirectCaller_RechecksCurrentAuthorityBeforeChangingAssignments(string fault, PrincipalWriteKind expected)
    {
        // Arrange
        await using var test = await CreateAsync();
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
        var service = new EligibilityService(test.Database.Context, test.Clock);
        var actor = new AdministrativeActor(snapshot, fault == "freshness" ? test.Clock.Now.AddMinutes(-11) : test.Clock.Now);
        var request = fault == "reason" ? new ChangeEligibilityRequest() : Reason();

        // Act
        var result = await service.RevokeAsync(target.PublicId, test.Resource.PublicId, ConfiguredEntitlement(test).PublicId, request, actor, target.Version, "direct-view");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Version);
        await AssertEligibilityUnchangedAsync(test, target.Id);
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task RevokeEligibility_InvalidHttpBoundary_DoesNotGrant(string fault)
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        if (fault == "csrf")
        {
            test.Client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        }
        var request = new ChangeEligibilityRequest
        {
            Reason = fault switch { "empty-reason" => string.Empty, "long-reason" => new string('x', 501), _ => "Review" }
        };

        // Act
        using var response = await RevokeAsync(test, target.PublicId, request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertEligibilityUnchangedAsync(test, target.Id);
    }

    [Fact]
    public async Task RevokeEligibility_UnknownPrincipal_ReturnsNotFound()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RevokeAsync(test, Guid.NewGuid());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertEligibilityUnchangedAsync(test, target.Id);
    }

    [Fact]
    public async Task RevokeEligibility_OpenApi_RequiresPrincipalVersionAndDocumentsSecurityErrors()
    {
        // Arrange
        await using var test = await CreateAsync();

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/eligibility/{resourceId}/{entitlementId}").GetProperty("delete");
        Assert.Equal("Principal.Eligibility.Revoke", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(), value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("inactive")]
    public async Task RevokeEligibility_AlreadyDesiredState_PreservesVersionWithoutCreatingRowsOrAudit(string state)
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        if (state == "absent")
        {
            await test.Database.Context.EligibilityRules.ExecuteDeleteAsync();
        }
        else
        {
            await test.Database.Context.EligibilityRules.ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, false));
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.Equal(etag, response.Headers.ETag.Tag);
        Assert.Equal(state == "absent" ? 0 : 1, await test.Database.Context.EligibilityRules.CountAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "eligibility.revoked"));
    }

    [Fact]
    public async Task RevokeEligibility_CurrentVersionRetry_DoesNotDuplicateAuditAndOldVersionFails()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var first = await RevokeAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.NoContent, first.StatusCode);
        using var stale = await RevokeAsync(test, target.PublicId);
        Assert.Equal(HttpStatusCode.PreconditionFailed, stale.StatusCode);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var retry = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, retry.StatusCode);
        Assert.Equal(first.Headers.ETag, retry.Headers.ETag);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "eligibility.revoked"));
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("roleless")]
    [InlineData("retired")]
    [InlineData("all")]
    public async Task RevokeEligibility_RetainedRule_StillAllowsPrivilegeReduction(string condition)
    {
        // Arrange
        await using var test = await CreateAsync();
        bool disabled = condition is "disabled" or "all";
        bool roleless = condition is "roleless" or "all";
        bool retired = condition is "retired" or "all";
        var target = await TargetAsync(test, enabled: !disabled);
        if (roleless)
        {
            await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).ExecuteDeleteAsync();
        }
        if (retired)
        {
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var binding = await test.Database.Context.EligibilityRules.IgnoreQueryFilters().AsNoTracking().SingleAsync();
        Assert.False(binding.IsEnabled);
        Assert.Equal(!disabled, await test.Database.Context.Principals.Where(value => value.Id == target.Id).Select(value => value.IsEnabled).SingleAsync());
        Assert.Equal(roleless ? 0 : 1, await test.Database.Context.PamRoleAssignments.CountAsync(value => value.PrincipalId == target.Id));
        Assert.Equal(retired, await test.Database.Context.ManagedResources.IgnoreQueryFilters().Where(value => value.Id == test.Resource.Id)
            .Select(value => value.DeletedAt != null).SingleAsync());
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("admin,user")]
    public async Task RevokeEligibility_OwnAssignment_AllowedWithoutChangingRoles(string roles)
    {
        // Arrange
        await using var test = await CreateAsync(roles: roles.Split(','));
        var target = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        {
            PrincipalId = test.ActorId,
            EntitlementId = ConfiguredEntitlement(test).Id,
            IsEnabled = true,
            CreatedAt = test.Clock.Now.UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync(value => value.IsEnabled));
        Assert.Equal(roles.Split(',').Order(), await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id)
            .Select(value => value.Role.Code).OrderBy(value => value).ToArrayAsync());
    }

    [Fact]
    public async Task RevokeEligibility_AuditRejected_RollsBackRuleAndParentVersion()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_view_revoke CHECK (event_type <> 'eligibility.revoked')");

        // Act
        using var response = await RevokeAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        await AssertEligibilityUnchangedAsync(test, target.Id);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
    }

    [Fact]
    public async Task RevokeEligibility_ActiveRule_PreservesViewSessionHistoryAndReplayButDeniesNewRequest()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        var entitlement = ConfiguredEntitlement(test);
        test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        using var requester = await LoginAsync(test, target.Id);
        using var csrf = await requester.GetAsync("/api/auth/antiforgery");
        SessionTestHost.UpdateCookie(requester, csrf);
        var tokens = await csrf.Content.ReadFromJsonAsync<Api.Authentication.AntiforgeryTokenResponse>();
        Assert.NotNull(tokens);
        requester.DefaultRequestHeaders.Add("X-CSRF-TOKEN", tokens.RequestToken);
        requester.DefaultRequestHeaders.Add("Idempotency-Key", "before-revocation");
        var request = new
        {
            resourceId = test.Resource.PublicId,
            entitlementId = entitlement.PublicId,
            requestedDurationMinutes = 30,
            justification = "Deploy release"
        };
        using var created = await requester.PostAsJsonAsync("/api/access-requests", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        string original = await created.Content.ReadAsStringAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await RevokeAsync(test, target.PublicId);
        using var detail = await requester.GetAsync(test.ResourceUrl);
        var requestable = await requester.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources?requestable=true");
        using var history = await requester.GetAsync(created.Headers.Location);
        using var replay = await requester.PostAsJsonAsync("/api/access-requests", request);
        requester.DefaultRequestHeaders.Remove("Idempotency-Key");
        requester.DefaultRequestHeaders.Add("Idempotency-Key", "after-revocation");
        using var deniedNew = await requester.PostAsJsonAsync("/api/access-requests", request);
        using var session = await requester.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(etag, response.Headers.ETag.Tag);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.NotNull(requestable);
        Assert.Empty(requestable.Items);
        Assert.Equal(HttpStatusCode.OK, history.StatusCode);
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(original, await replay.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Created, deniedNew.StatusCode);
        var denied = await deniedNew.Content.ReadFromJsonAsync<Application.AccessRequests.AccessRequestResponse>();
        Assert.NotNull(denied);
        Assert.Equal("Denied", denied.State);
        Assert.Equal(HttpStatusCode.OK, session.StatusCode);
        Assert.Equal(2, await test.Database.Context.AccessRequests.CountAsync());
        Assert.True(await test.Database.Context.ResourcePrincipalBindings.Select(value => value.IsActive).SingleAsync());
        var rule = await test.Database.Context.EligibilityRules.AsNoTracking().SingleAsync();
        Assert.False(rule.IsEnabled);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "eligibility.revoked");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal(entitlement.Id, audit.EntitlementId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(rule.PublicId, metadata.RootElement.GetProperty("eligibilityId").GetGuid());
        Assert.True(metadata.RootElement.GetProperty("before").GetBoolean());
        Assert.False(metadata.RootElement.GetProperty("after").GetBoolean());
        Assert.Equal("Reviewed eligibility", metadata.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task RevokeEligibility_WrongResourceParent_DoesNotDisableTheOriginalRule()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        var other = new ManagedResource
        {
            Name = "Other",
            ResourceType = "linux",
            Environment = "dev",
            CreatedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        };
        test.Database.Context.ManagedResources.Add(other);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);
        using var message = new HttpRequestMessage(HttpMethod.Delete,
            $"/api/principals/{target.PublicId}/eligibility/{other.PublicId}/{ConfiguredEntitlement(test).PublicId}")
        { Content = JsonContent.Create(Reason()) };

        // Act
        using var response = await test.Client.SendAsync(message);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertEligibilityUnchangedAsync(test, target.Id);
    }

    private async Task<ResourceTestContext> CreateAsync(string[]? roles = null)
    {
        var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: roles);
        test.Database.Context.Entitlements.Add(new Entitlement
        {
            Resource = test.Resource,
            Code = "read",
            Name = "Read",
            IsActive = true,
            MaxDurationMinutes = 60,
            RequiresApproval = true
        });
        await test.Database.Context.SaveChangesAsync();
        return test;
    }

    private static Entitlement ConfiguredEntitlement(ResourceTestContext test) => test.Resource.Entitlements.Single();

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
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        {
            PrincipalId = target.Id,
            EntitlementId = ConfiguredEntitlement(test).Id,
            IsEnabled = true,
            CreatedAt = test.Clock.Now.UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
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
        using var response = await test.Client.GetAsync($"/api/principals/{id}/eligibility");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(response.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(response.Headers.ETag);
        return response.Headers.ETag.Tag;
    }

    private static string Url(ResourceTestContext test, Guid id) =>
        $"/api/principals/{id}/eligibility/{test.Resource.PublicId}/{ConfiguredEntitlement(test).PublicId}";

    private static async Task<HttpResponseMessage> RevokeAsync(ResourceTestContext test, Guid id, ChangeEligibilityRequest? request = null)
    {
        using var message = new HttpRequestMessage(HttpMethod.Delete, Url(test, id))
        { Content = JsonContent.Create(request ?? Reason()) };
        return await test.Client.SendAsync(message);
    }

    private static ChangeEligibilityRequest Reason() => new() { Reason = " Reviewed eligibility " };

    private static async Task AssertEligibilityUnchangedAsync(ResourceTestContext test, long targetId)
    {
        Assert.True(await test.Database.Context.EligibilityRules.AnyAsync(value => value.PrincipalId == targetId && value.IsEnabled));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "eligibility.revoked"));
    }
}
