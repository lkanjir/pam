using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Application.Authorization;
using Application.Common.Pagination;
using Application.Resources;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Npgsql;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class ResourceVisibilityTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("user", true, true, 200)]
    [InlineData("approver", true, true, 200)]
    [InlineData("user", false, true, 404)]
    [InlineData("user", true, false, 404)]
    [InlineData("approver", false, true, 404)]
    [InlineData("superadmin", true, true, 403)]
    [InlineData("", true, true, 403)]
    public async Task Get_ScopedReader_RequiresCurrentExplicitViewBinding(string role, bool assigned, bool active, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection,
            roles: role.Length == 0 ? [] : [role]);
        if (assigned)
        {
            test.AddViewBinding(test.Resource).IsActive = active;
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        if (status == 200)
        {
            var resource = await response.Content.ReadFromJsonAsync<ResourceResponse>();
            Assert.NotNull(resource);
            Assert.Equal(test.Resource.PublicId, resource.Id);
            Assert.NotNull(response.Headers.ETag);
        }
        else
        {
            Assert.Null(response.Headers.ETag);
            Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Get_ForeignViewBinding_DoesNotRevealResource()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        test.AddViewBinding(test.Resource, test.Resource.CreatedByPrincipalId);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("retired")]
    public async Task Get_UnavailableResource_IsIndistinguishableFromHiddenResource(string unavailable)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        test.AddViewBinding(test.Resource);
        if (unavailable == "retired")
        {
            test.Resource.DeletedAt = test.Clock.Now.UtcDateTime;
        }
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        string url = unavailable == "missing" ? $"/api/resources/{Guid.NewGuid()}" : test.ResourceUrl;

        // Act
        using var response = await test.Client.GetAsync(url);

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Null(response.Headers.ETag);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(404, body.RootElement.GetProperty("status").GetInt32());
        Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Get_AdminAndUser_ManagementReadDoesNotImplyRequesterVisibility()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var entitlement = await SeedEntitlementAsync(test);
        await test.Database.Context.ResourcePrincipalBindings.ExecuteDeleteAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var management = await test.Client.GetAsync(test.ResourceUrl);
        using var requestable = await test.Client.GetAsync("/api/resources?requestable=true");
        using var submission = await PostAsync(test, Request(test, entitlement));

        // Assert
        Assert.Equal(HttpStatusCode.OK, management.StatusCode);
        Assert.Equal(HttpStatusCode.OK, requestable.StatusCode);
        var page = await requestable.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
        Assert.NotNull(page);
        Assert.Empty(page.Items);
        Assert.Equal(HttpStatusCode.NotFound, submission.StatusCode);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task ListRequestable_ViewWithoutEligibilityAndEligibilityWithoutView_AreIndependent()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        await SeedEntitlementAsync(test);
        await test.Database.Context.ResourcePrincipalBindings.ExecuteUpdateAsync(update => update.SetProperty(value => value.IsActive, false));
        await test.AuthenticateAsync(includeResourceVersion: false);
        using var eligibilityOnly = await test.Client.GetAsync("/api/resources?requestable=true");
        Assert.Equal(HttpStatusCode.OK, eligibilityOnly.StatusCode);
        var first = await eligibilityOnly.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
        Assert.NotNull(first);
        Assert.Empty(first.Items);
        await test.Database.Context.ResourcePrincipalBindings.ExecuteUpdateAsync(update => update.SetProperty(value => value.IsActive, true));
        await test.Database.Context.EligibilityRules.ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, false));

        // Act
        using var viewOnly = await test.Client.GetAsync("/api/resources?requestable=true");
        using var detail = await test.Client.GetAsync(test.ResourceUrl);

        // Assert
        Assert.Equal(HttpStatusCode.OK, viewOnly.StatusCode);
        var second = await viewOnly.Content.ReadFromJsonAsync<CursorPage<ResourceResponse>>();
        Assert.NotNull(second);
        Assert.Empty(second.Items);
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
    }

    [Fact]
    public async Task ListRequestable_HiddenRowsBetweenVisibleRows_AreFilteredBeforeCursorPagination()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        var first = AddResource(test, 1, visible: true);
        AddResource(test, 2, visible: false);
        var last = AddResource(test, 3, visible: true);
        AddResource(test, 4, visible: false);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        var page = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>("/api/resources?requestable=true&limit=1");
        Assert.NotNull(page);
        Assert.NotNull(page.NextCursor);
        Assert.Equal(first.PublicId, Assert.Single(page.Items).Id);

        // Act
        var continuation = await test.Client.GetFromJsonAsync<CursorPage<ResourceResponse>>(
            "/api/resources?requestable=true&limit=1&cursor=" + Uri.EscapeDataString(page.NextCursor));

        // Assert
        Assert.NotNull(continuation);
        Assert.Equal(last.PublicId, Assert.Single(continuation.Items).Id);
        Assert.Null(continuation.NextCursor);
    }

    [Theory]
    [InlineData("absent")]
    [InlineData("inactive")]
    [InlineData("foreign")]
    public async Task Submit_InvisibleResource_ReturnsNotFoundWithoutPolicyOrRequestAudit(string visibility)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        var entitlement = await SeedEntitlementAsync(test);
        await test.Database.Context.ResourcePrincipalBindings.ExecuteDeleteAsync();
        if (visibility != "absent")
        {
            var binding = new ResourcePrincipalBinding
            {
                ResourceId = test.Resource.Id,
                PrincipalId = visibility == "foreign" ? test.Resource.CreatedByPrincipalId : test.ActorId,
                Kind = ResourceBindingKind.ViewResource,
                IsActive = visibility != "inactive",
                AssignedByPrincipalId = test.ActorId,
                ModifiedByPrincipalId = test.ActorId,
                AssignedAt = test.Clock.Now.UtcDateTime,
                ModifiedAt = test.Clock.Now.UtcDateTime
            };
            test.Database.Context.ResourcePrincipalBindings.Add(binding);
            await test.Database.Context.SaveChangesAsync();
        }
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await PostAsync(test, Request(test, entitlement));

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("Original target", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        await AssertNoRequestsAsync(test);
    }

    [Fact]
    public async Task Submit_VisibilityRemovedAfterCreation_ReplaysOriginalAndPreservesOwnerHistory()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["user"]);
        var entitlement = await SeedEntitlementAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);
        var request = Request(test, entitlement);
        using var created = await PostAsync(test, request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        string saved = await created.Content.ReadAsStringAsync();
        await test.Database.Context.ResourcePrincipalBindings.ExecuteUpdateAsync(update => update.SetProperty(value => value.IsActive, false));

        // Act
        using var replay = await PostAsync(test, request);
        using var detail = await test.Client.GetAsync(created.Headers.Location);
        using var history = await test.Client.GetAsync("/api/access-requests/mine");
        using var newRequest = await PostAsync(test, request, "new-command");

        // Assert
        Assert.Equal(HttpStatusCode.OK, replay.StatusCode);
        Assert.Equal(saved, await replay.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.OK, detail.StatusCode);
        Assert.Equal(HttpStatusCode.OK, history.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, newRequest.StatusCode);
        Assert.Equal(1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.Equal(2, await test.Database.Context.AuditEvents.CountAsync(value => value.RequestId != null));
    }

    [Fact]
    public async Task Remove_LastScopedReadBundle_DeactivatesViewAndRegrantDoesNotRestoreIt()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await test.Database.Context.Principals.SingleAsync(value => value.Subject == "ivan");
        await test.Database.Context.Principals.Where(value => value.Id == target.Id)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user");
        var binding = test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetPrincipalVersionAsync(test, target.PublicId);
        using var delete = new HttpRequestMessage(HttpMethod.Delete, $"/api/principals/{target.PublicId}/roles/user")
        { Content = JsonContent.Create(new { reason = "Remove requester support" }) };
        using var removed = await test.Client.SendAsync(delete);
        Assert.Equal(HttpStatusCode.OK, removed.StatusCode);
        await SetPrincipalVersionAsync(test, target.PublicId);

        // Act
        using var granted = await test.Client.PutAsJsonAsync($"/api/principals/{target.PublicId}/roles/user", new { reason = "Restore role only" });

        // Assert
        Assert.Equal(HttpStatusCode.OK, granted.StatusCode);
        var persisted = await test.Database.Context.ResourcePrincipalBindings.AsNoTracking().SingleAsync(value => value.Id == binding.Id);
        Assert.False(persisted.IsActive);
        Assert.Equal(test.ActorId, persisted.ModifiedByPrincipalId);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "resource_access.deactivated");
        Assert.Equal(target.Id, audit.SubjectPrincipalId);
        Assert.Equal(test.Resource.Id, audit.ResourceId);
        Assert.NotNull(audit.Metadata);
        using var metadata = JsonDocument.Parse(audit.Metadata);
        Assert.Equal(binding.PublicId, metadata.RootElement.GetProperty("bindingId").GetGuid());
        Assert.Equal("supporting_role_removed", audit.ReasonCode);
    }

    [Theory]
    [InlineData("user", "approver")]
    [InlineData("approver", "user")]
    public async Task Remove_AnotherExplicitBundleStillSupportsScopedRead_RetainsView(string removedCode, string retainedCode)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await test.Database.Context.Principals.SingleAsync(value => value.Subject == "ivan");
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user", "approver");
        var binding = test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetPrincipalVersionAsync(test, target.PublicId);
        using var delete = new HttpRequestMessage(HttpMethod.Delete, $"/api/principals/{target.PublicId}/roles/{removedCode}")
        { Content = JsonContent.Create(new { reason = "Retain other explicit read bundle" }) };

        // Act
        using var response = await test.Client.SendAsync(delete);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await test.Database.Context.ResourcePrincipalBindings.Where(value => value.Id == binding.Id).Select(value => value.IsActive).SingleAsync());
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == target.Id && value.Role.Code == retainedCode));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "resource_access.deactivated"));
    }

    [Fact]
    public async Task Remove_RequiredViewAuditFails_RollsBackRoleAndBinding()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = await test.Database.Context.Principals.SingleAsync(value => value.Subject == "ivan");
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "user");
        var binding = test.AddViewBinding(test.Resource, target.Id);
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_view_audit CHECK (event_type <> 'resource_access.deactivated')");
        await test.AuthenticateAsync(includeResourceVersion: false);
        await SetPrincipalVersionAsync(test, target.PublicId);
        using var delete = new HttpRequestMessage(HttpMethod.Delete, $"/api/principals/{target.PublicId}/roles/user")
        { Content = JsonContent.Create(new { reason = "Must roll back together" }) };

        // Act
        using var response = await test.Client.SendAsync(delete);

        // Assert
        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.True(await test.Database.Context.ResourcePrincipalBindings.Where(value => value.Id == binding.Id).Select(value => value.IsActive).SingleAsync());
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.PrincipalId == target.Id && value.Role.Code == "user"));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "role.removed"));
    }

    [Theory]
    [InlineData("duplicate", PostgresErrorCodes.UniqueViolation)]
    [InlineData("unknown-kind", PostgresErrorCodes.CheckViolation)]
    public async Task Persist_InvalidRelationship_IsRejectedByPostgreSql(string invalid, string expectedSqlState)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        test.AddViewBinding(test.Resource);
        await test.Database.Context.SaveChangesAsync();
        test.Database.Context.ResourcePrincipalBindings.Add(new ResourcePrincipalBinding
        {
            PrincipalId = test.ActorId,
            ResourceId = test.Resource.Id,
            Kind = invalid == "duplicate" ? ResourceBindingKind.ViewResource : (ResourceBindingKind)999,
            AssignedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            AssignedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        });

        // Act
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => test.Database.Context.SaveChangesAsync());

        // Assert
        var postgresError = Assert.IsType<PostgresException>(error.InnerException);
        Assert.Equal(expectedSqlState, postgresError.SqlState);
    }

    private static async Task SetPrincipalVersionAsync(ResourceTestContext test, Guid id)
    {
        using var principal = await test.Client.GetAsync($"/api/principals/{id}");
        Assert.Equal(HttpStatusCode.OK, principal.StatusCode);
        Assert.NotNull(principal.Headers.ETag);
        test.Client.DefaultRequestHeaders.IfMatch.Clear();
        test.Client.DefaultRequestHeaders.IfMatch.Add(principal.Headers.ETag);
    }

    private static ManagedResource AddResource(ResourceTestContext test, int suffix, bool visible)
    {
        var resource = new ManagedResource
        {
            PublicId = Guid.Parse("00000000-0000-7000-8000-" + suffix.ToString("D12", System.Globalization.CultureInfo.InvariantCulture)),
            Name = "Resource " + suffix.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ResourceType = "linux",
            Environment = "dev",
            IsActive = true,
            CreatedByPrincipalId = test.ActorId,
            ModifiedByPrincipalId = test.ActorId,
            CreatedAt = test.Clock.Now.UtcDateTime,
            ModifiedAt = test.Clock.Now.UtcDateTime
        };
        test.Database.Context.ManagedResources.Add(resource);
        test.Database.Context.EligibilityRules.Add(new EligibilityRule
        {
            PrincipalId = test.ActorId,
            IsEnabled = true,
            Entitlement = new Entitlement
            {
                Resource = resource,
                Code = "read",
                Name = "Read",
                IsActive = true,
                MaxDurationMinutes = 60,
                RequiresApproval = true
            }
        });
        if (visible)
        {
            test.AddViewBinding(resource);
        }
        return resource;
    }
}
