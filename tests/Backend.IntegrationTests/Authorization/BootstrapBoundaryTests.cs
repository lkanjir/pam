using System.Net;
using System.Net.Http.Json;
using Application.Authorization;
using Application.Bootstrap;
using Application.Principals;
using Application.Resources;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Infrastructure.Authentication;
using Infrastructure.Identity;
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Infrastructure.Resources;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class BootstrapBoundaryTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("/api/resources")]
    [InlineData("/api/resources/visible")]
    [InlineData("/api/access-requests/mine")]
    public async Task Get_BootstrapWithExtraBundles_CannotUseBusinessCatalogs(string path)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: ["admin", "user", "approver"]);
        await BootstrapTestData.MarkActorAsync(test);
        test.AddViewBinding(test.Resource);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var response = await test.Client.GetAsync(path);

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.DoesNotContain(test.Resource.PublicId.ToString(), await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Bootstrap_SetupOnly_CanMapEnableAndAssignPermanentAdminWithoutSelfGrant()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await BootstrapTestData.MarkActorAsync(test);
        await test.AuthenticateAsync(includeResourceVersion: false);

        // Act
        using var created = await test.Client.PostAsJsonAsync("/api/principals", new CreatePrincipalRequest
        {
            Issuer = "https://identity.example/realms/pam",
            Subject = "permanent-admin",
            DisplayName = "Permanent admin",
            Reason = "Prepare actual administrator"
        });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var principal = await created.Content.ReadFromJsonAsync<PrincipalResponse>();
        Assert.NotNull(principal);
        await test.RefreshVersionAsync($"/api/principals/{principal.Id}");
        using var enabled = await test.Client.PostAsJsonAsync($"/api/principals/{principal.Id}/enable",
            new ChangePrincipalStatusRequest { Reason = "Verified identity" });
        Assert.Equal(HttpStatusCode.OK, enabled.StatusCode);
        await test.RefreshVersionAsync($"/api/principals/{principal.Id}");
        using var assigned = await test.Client.PutAsJsonAsync($"/api/principals/{principal.Id}/roles/admin",
            new ChangePrincipalRoleRequest { Reason = "Initial permanent administrator" });

        // Assert
        Assert.Equal(HttpStatusCode.OK, assigned.StatusCode);
        Assert.True(await test.Database.Context.Principals.AnyAsync(value => value.PublicId == principal.Id && value.IsEnabled));
        Assert.True(await test.Database.Context.PamRoleAssignments.AnyAsync(value => value.Principal.PublicId == principal.Id && value.Role.Code == "admin"));
        Assert.Null((await test.Database.Context.PamInstallations.SingleAsync()).CompletedAt);
        Assert.Equal(3, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "principal.mapped"
            || value.EventType == "principal.enabled" || value.EventType == "role.assigned"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Get_State_IsReadOnlyAndDoesNotInitializeLegacyInstallation(bool initialized)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        if (initialized)
        {
            await BootstrapTestData.MarkActorAsync(test);
        }
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);

        // Act
        using var response = await test.Client.GetAsync("/api/authorization/bootstrap");

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var state = await response.Content.ReadFromJsonAsync<BootstrapStateResponse>();
        Assert.NotNull(state);
        Assert.Equal(initialized, state.IsInitialized);
        Assert.Equal(initialized, state.IsPending);
        Assert.Equal(initialized, response.Headers.ETag is not null);
        Assert.Null(state.Version);
        Assert.Null(state.CompletedAt);
        Assert.Equal(initialized ? 1 : 0, await test.Database.Context.PamInstallations.CountAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType.StartsWith("bootstrap.")));
    }

    [Theory]
    [InlineData("user", true, 403)]
    [InlineData("approver", true, 403)]
    [InlineData("admin", false, 401)]
    public async Task Get_State_RequiresExplicitAuthenticatedAdmin(string role, bool login, int status)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection, roles: [role]);
        if (login)
        {
            await test.AuthenticateAsync(includeResourceVersion: false);
        }

        // Act
        using var response = await test.Client.GetAsync("/api/authorization/bootstrap");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.DoesNotContain("bootstrapPrincipalId", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cookie_InstallationKindChanges_RejectsExistingPermanentCookie()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await test.AuthenticateAsync(includeResourceVersion: false);
        await BootstrapTestData.MarkActorAsync(test);

        // Act
        using var response = await test.Client.GetAsync("/api/principals");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("disable")]
    [InlineData("role-remove")]
    public async Task Bootstrap_ReductiveAdminOperations_AreForbiddenEvenThroughDirectServices(string operation)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await BootstrapTestData.MarkActorAsync(test);
        var target = Principal.CreateMapping("issuer", "target", "Target", test.Clock.Now);
        test.Database.Context.Principals.Add(target);
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await test.RefreshVersionAsync($"/api/principals/{target.PublicId}");
        var source = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var actor = new AdministrativeActor(new PrincipalSnapshot(source.Id, source.PublicId, source.DisplayName, source.Issuer, source.Subject), test.Clock.Now);
        await using var scope = test.CreateScope();
        var tickets = scope.ServiceProvider.GetRequiredService<ISessionTicketStore>();

        // Act
        using var request = new HttpRequestMessage(operation == "disable" ? HttpMethod.Post : HttpMethod.Delete,
            operation == "disable" ? $"/api/principals/{target.PublicId}/disable" : $"/api/principals/{target.PublicId}/roles/user")
        { Content = JsonContent.Create(new { reason = "Must be forbidden" }) };
        using var response = await test.Client.SendAsync(request);
        var kind = operation == "disable"
            ? (await new PrincipalAdministrationService(test.Database.Context, test.Clock, tickets).DisableAsync(target.PublicId,
                new ChangePrincipalStatusRequest { Reason = "Must be forbidden" }, actor, target.Version, "direct")).Kind
            : (await new PrincipalRoleService(test.Database.Context, test.Clock, tickets).RemoveAsync(target.PublicId, "user",
                new ChangePrincipalRoleRequest { Reason = "Must be forbidden" }, actor, target.Version, "direct")).Kind;

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Equal(PrincipalWriteKind.Forbidden, kind);
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.SubjectPrincipalId == target.Id));
    }

    [Fact]
    public async Task Bootstrap_DirectResourceMutation_RechecksDatabaseInstallationBoundary()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await BootstrapTestData.MarkActorAsync(test);
        var source = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var actor = new AdministrativeActor(new PrincipalSnapshot(source.Id, source.PublicId, source.DisplayName, source.Issuer, source.Subject), test.Clock.Now);

        // Act
        var result = await new ResourceService(test.Database.Context, test.Clock).DeleteAsync(test.Resource.PublicId,
            actor, "direct", test.Resource.Version);

        // Assert
        Assert.Equal(ResourceWriteKind.Forbidden, result);
        Assert.Null((await test.ReadResourceAsync()).DeletedAt);
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.EventType == "resource.deleted"));
    }

    [Theory]
    [InlineData("enable")]
    [InlineData("disable")]
    [InlineData("role-assign")]
    [InlineData("role-remove")]
    [InlineData("view-assign")]
    [InlineData("authority-assign")]
    public async Task PermanentAdmin_NormalMutationsCannotChangeBootstrapIdentity(string operation)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var target = Principal.CreateMapping("issuer", "installer", "Installer", test.Clock.Now);
        test.Database.Context.Principals.Add(target);
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Principals.Where(value => value.Id == target.Id)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        await SessionTestHost.AssignRolesAsync(test.Database, target.Id, "admin", "user");
        test.Database.Context.PamInstallations.Add(new PamInstallation { BootstrapPrincipalId = target.Id, InitializedAt = test.Clock.Now.UtcDateTime });
        await test.Database.Context.SaveChangesAsync();
        await test.AuthenticateAsync(includeResourceVersion: false);
        await test.RefreshVersionAsync($"/api/principals/{target.PublicId}");
        string suffix = operation switch
        {
            "enable" or "disable" => operation,
            "view-assign" => $"resource-access/{test.Resource.PublicId}",
            "authority-assign" => $"approval-authority/{test.Resource.PublicId}",
            _ => "roles/user"
        };
        var method = operation is "enable" or "disable" ? HttpMethod.Post : operation == "role-remove" ? HttpMethod.Delete : HttpMethod.Put;

        // Act
        using var request = new HttpRequestMessage(method, $"/api/principals/{target.PublicId}/{suffix}")
        { Content = JsonContent.Create(new { reason = "Normal endpoint cannot alter installation identity" }) };
        using var response = await test.Client.SendAsync(request);

        // Assert
        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        Assert.Contains("bootstrap_identity_protected", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync(value => value.SubjectPrincipalId == target.Id));
    }

    [Fact]
    public async Task Identity_CompletedInstallation_RemainsUnauthenticatableAfterManualPhysicalEnable()
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        await BootstrapTestData.MarkActorAsync(test);
        await test.Database.Context.PamInstallations.ExecuteUpdateAsync(update => update
            .SetProperty(value => value.CompletedAt, test.Clock.Now.UtcDateTime)
            .SetProperty(value => value.CompletedByPrincipalId, test.ActorId));

        // Act
        var source = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var identity = await new PrincipalIdentityReader(test.Database.Context).FindAsync(source.Issuer, source.Subject);

        // Assert
        Assert.True(source.IsEnabled);
        Assert.NotNull(identity);
        Assert.True(identity.IsBootstrap);
        Assert.False(identity.IsEnabled);
    }
}
