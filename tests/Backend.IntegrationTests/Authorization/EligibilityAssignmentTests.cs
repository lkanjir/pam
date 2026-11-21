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
public sealed class EligibilityAssignmentTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, true, 0, 403)]
    [InlineData("approver", true, true, 0, 403)]
    [InlineData("superadmin", true, true, 0, 403)]
    [InlineData("", true, true, 0, 403)]
    [InlineData("admin", false, true, 0, 401)]
    [InlineData("admin", true, false, 0, 403)]
    [InlineData("admin", true, true, 601, 403)]
    public async Task AssignEligibility_WithoutPermissionOrRecentAuthentication_DoesNotGrant(string role, bool login,
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
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Theory]
    [InlineData(null, 428)]
    [InlineData("invalid", 400)]
    [InlineData("\"00000001\"", 412)]
    public async Task AssignEligibility_WithoutCurrentPrincipalVersion_DoesNotGrant(string? version, int status)
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
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Theory]
    [InlineData("role", PrincipalWriteKind.Forbidden)]
    [InlineData("disabled", PrincipalWriteKind.Forbidden)]
    [InlineData("identity", PrincipalWriteKind.Forbidden)]
    [InlineData("freshness", PrincipalWriteKind.RecentAuthenticationRequired)]
    [InlineData("reason", PrincipalWriteKind.InvalidRequest)]
    public async Task AssignEligibility_DirectCaller_RechecksCurrentAuthorityBeforeChangingAssignments(string fault, PrincipalWriteKind expected)
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
        var result = await service.AssignAsync(target.PublicId, test.Resource.PublicId, ConfiguredEntitlement(test).PublicId, request, actor, target.Version, "direct-view");

        // Assert
        Assert.Equal(expected, result.Kind);
        Assert.Null(result.Version);
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Theory]
    [InlineData("csrf")]
    [InlineData("empty-reason")]
    [InlineData("long-reason")]
    public async Task AssignEligibility_InvalidHttpBoundary_DoesNotGrant(string fault)
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
        using var response = await test.Client.PutAsJsonAsync(Url(test, target.PublicId), request);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignEligibility_UnknownPrincipal_ReturnsNotFound()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, Guid.NewGuid());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignEligibility_OpenApi_RequiresPrincipalVersionAndDocumentsSecurityErrors()
    {
        // Arrange
        await using var test = await CreateAsync();

        // Act
        using var response = await test.Client.GetAsync("/openapi/v1.json");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var operation = json.RootElement.GetProperty("paths").GetProperty("/api/principals/{id}/eligibility/{resourceId}/{entitlementId}").GetProperty("put");
        Assert.Equal("Principal.Eligibility.Assign", operation.GetProperty("operationId").GetString());
        var header = Assert.Single(operation.GetProperty("parameters").EnumerateArray(), value => value.GetProperty("name").GetString() == "If-Match");
        Assert.True(header.GetProperty("required").GetBoolean());
        Assert.True(operation.GetProperty("responses").TryGetProperty("409", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("412", out _));
        Assert.True(operation.GetProperty("responses").TryGetProperty("428", out _));
    }

    [Fact]
    public async Task AssignEligibility_VisibleRequester_BecomesRequestableInSameSessionWithAtomicAudit()
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
        var before = await requester.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources?requestable=true");
        Assert.NotNull(before);
        Assert.Empty(before.Items);
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var granted = await AssignAsync(test, target.PublicId);
        var page = await requester.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources?requestable=true");
        requester.DefaultRequestHeaders.Add("Idempotency-Key", "after-eligibility");
        using var submission = await requester.PostAsJsonAsync("/api/access-requests", new
        {
            resourceId = test.Resource.PublicId,
            entitlementId = entitlement.PublicId,
            requestedDurationMinutes = 30,
            justification = "Deploy release"
        });

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, granted.StatusCode);
        Assert.NotNull(granted.Headers.ETag);
        Assert.NotEqual(etag, granted.Headers.ETag.Tag);
        Assert.NotNull(page);
        var resource = Assert.Single(page.Items);
        Assert.NotNull(resource.Entitlements);
        Assert.Equal(entitlement.PublicId, Assert.Single(resource.Entitlements).Id);
        Assert.Equal(HttpStatusCode.Created, submission.StatusCode);
        var created = await submission.Content.ReadFromJsonAsync<Application.AccessRequests.AccessRequestResponse>();
        Assert.NotNull(created);
        Assert.Equal("PendingApproval", created.State);
        var rule = await test.Database.Context.EligibilityRules.AsNoTracking().SingleAsync();
        Assert.Equal(target.Id, rule.PrincipalId);
        Assert.Equal(entitlement.Id, rule.EntitlementId);
        Assert.True(rule.IsEnabled);
        Assert.Equal(test.Clock.Now.UtcDateTime, rule.CreatedAt);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "eligibility.granted");
        Assert.Equal(test.ActorId, audit.ActorPrincipalId);
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.Equal(entitlement.Id, audit.EntitlementId);
        Assert.Equal(ResourceTestContext.CorrelationId, audit.CorrelationId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(rule.PublicId, metadata.RootElement.GetProperty("eligibilityId").GetGuid());
        Assert.False(metadata.RootElement.GetProperty("before").GetBoolean());
        Assert.True(metadata.RootElement.GetProperty("after").GetBoolean());
        Assert.Equal("Reviewed eligibility", metadata.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task AssignEligibility_WithoutView_DoesNotRevealResourceOrGrantRoles()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        using var requester = await LoginAsync(test, target.Id);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var granted = await AssignAsync(test, target.PublicId);
        using var hidden = await requester.GetAsync(test.ResourceUrl);
        var requestable = await requester.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources?requestable=true");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, granted.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, hidden.StatusCode);
        Assert.NotNull(requestable);
        Assert.Empty(requestable.Items);
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync());
        Assert.Equal("user", await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id).Select(value => value.Role.Code).SingleAsync());
    }

    [Theory]
    [InlineData("admin,user", 204)]
    [InlineData("admin,approver", 409)]
    [InlineData("admin", 409)]
    public async Task AssignEligibility_OwnAccount_RequiresExistingRequesterCapability(string roles, int status)
    {
        // Arrange
        await using var test = await CreateAsync(roles.Split(','));
        var target = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal(status == 204, await test.Database.Context.EligibilityRules.AnyAsync(value => value.PrincipalId == target.Id && value.IsEnabled));
        Assert.Equal(roles.Split(',').Order(), await test.Database.Context.PamRoleAssignments.Where(value => value.PrincipalId == target.Id)
            .Select(value => value.Role.Code).OrderBy(value => value).ToArrayAsync());
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync());
    }

    [Fact]
    public async Task AssignEligibility_CurrentVersionRetry_PreservesVersionAndOldVersionFails()
    {
        // Arrange
        await using var test = await CreateAsync();
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
        Assert.Equal(1, await test.Database.Context.EligibilityRules.CountAsync());
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "eligibility.granted"));
    }

    [Fact]
    public async Task AssignEligibility_DisabledRule_ReactivatesSameIdentityWithoutRewritingCreationTime()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        var rule = AddDisabledRule(test, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        var updated = await test.Database.Context.EligibilityRules.AsNoTracking().SingleAsync();
        Assert.Equal(rule.PublicId, updated.PublicId);
        Assert.Equal(test.Clock.Now.AddHours(-1).UtcDateTime, updated.CreatedAt);
        Assert.True(updated.IsEnabled);
        Assert.NotNull(response.Headers.ETag);
        Assert.NotEqual(etag, response.Headers.ETag.Tag);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AssignEligibility_RequiredAuditRejected_RollsBackNewOrRetainedRuleAndParentVersion(bool retained)
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        if (retained)
        {
            AddDisabledRule(test, target.Id);
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        string etag = await SetVersionAsync(test, target.PublicId);
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_eligibility_grant CHECK (event_type <> 'eligibility.granted')");

        // Act
        using var response = await AssignAsync(test, target.PublicId);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal(etag, await SetVersionAsync(test, target.PublicId));
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync(value => value.IsEnabled));
        Assert.Equal(retained ? 1 : 0, await test.Database.Context.EligibilityRules.CountAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "eligibility.granted"));
    }

    [Theory]
    [InlineData("disabled", "target_disabled")]
    [InlineData("approver", "target_missing_capability")]
    [InlineData("admin", "target_missing_capability")]
    public async Task AssignEligibility_UnsupportedTarget_DoesNotGrant(string fault, string code)
    {
        // Arrange
        await using var test = await CreateAsync();
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
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Theory]
    [InlineData("missing-resource")]
    [InlineData("retired-resource")]
    [InlineData("missing-entitlement")]
    [InlineData("wrong-parent")]
    public async Task AssignEligibility_UnavailableOrMismatchedParent_DoesNotGrant(string fault)
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        Guid resourceId = test.Resource.PublicId;
        Guid entitlementId = ConfiguredEntitlement(test).PublicId;
        if (fault == "missing-resource")
        {
            resourceId = Guid.NewGuid();
        }
        if (fault == "missing-entitlement")
        {
            entitlementId = Guid.NewGuid();
        }
        if (fault == "retired-resource")
        {
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
            await test.Database.Context.SaveChangesAsync();
        }
        if (fault == "wrong-parent")
        {
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
            resourceId = other.PublicId;
        }
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/eligibility/{resourceId}/{entitlementId}", Reason());

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        await AssertNoEligibilityAsync(test, target.Id);
    }

    [Fact]
    public async Task AssignEligibility_InactiveConfiguration_CanBePreparedWithoutBecomingRequestable()
    {
        // Arrange
        await using var test = await CreateAsync();
        var target = await TargetAsync(test);
        test.Resource.IsActive = false;
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Entitlements.ExecuteUpdateAsync(update => update.SetProperty(value => value.IsActive, false));
        test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        using var requester = await LoginAsync(test, target.Id);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetVersionAsync(test, target.PublicId);

        // Act
        using var response = await AssignAsync(test, target.PublicId);
        var page = await requester.GetFromJsonAsync<Application.Common.Pagination.CursorPage<Application.Resources.ResourceResponse>>("/api/resources?requestable=true");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(await test.Database.Context.EligibilityRules.Select(value => value.IsEnabled).SingleAsync());
        Assert.NotNull(page);
        Assert.Empty(page.Items);
    }

    private static EligibilityRule AddDisabledRule(ResourceTestContext test, long principalId)
    {
        var rule = new EligibilityRule
        {
            PrincipalId = principalId,
            EntitlementId = ConfiguredEntitlement(test).Id,
            IsEnabled = false,
            CreatedAt = test.Clock.Now.AddHours(-1).UtcDateTime
        };
        test.Database.Context.EligibilityRules.Add(rule);
        return rule;
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

    private static Task<HttpResponseMessage> AssignAsync(ResourceTestContext test, Guid id) =>
        test.Client.PutAsJsonAsync(Url(test, id), Reason());

    private static ChangeEligibilityRequest Reason() => new() { Reason = " Reviewed eligibility " };

    private static async Task AssertNoEligibilityAsync(ResourceTestContext test, long targetId)
    {
        Assert.False(await test.Database.Context.EligibilityRules.AnyAsync(value => value.PrincipalId == targetId));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "eligibility.granted"));
    }
}
