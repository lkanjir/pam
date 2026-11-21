using System.Security.Claims;
using Api.Authentication;
using Api.Authorization;
using Application.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Backend.UnitTests.Authorization;

public sealed class PermissionPolicyTests
{
    [Theory]
    [InlineData(PamPermissions.ResourcesManage, true)]
    [InlineData(PamPermissions.PrincipalsManage, true)]
    [InlineData(PamPermissions.RolesAssign, true)]
    [InlineData(PamPermissions.ResourceAccessAssign, true)]
    [InlineData(PamPermissions.EligibilityAssign, true)]
    [InlineData(PamPermissions.ApprovalAuthorityAssign, true)]
    [InlineData(PamPermissions.ResourcesReadAll, false)]
    [InlineData(PamPermissions.ResourcesReadScoped, false)]
    [InlineData(PamPermissions.PrincipalsRead, false)]
    [InlineData(PamPermissions.RolesRead, false)]
    [InlineData(PamPermissions.ResourceAccessRead, false)]
    [InlineData(PamPermissions.EligibilityRead, false)]
    [InlineData(PamPermissions.ApprovalAuthorityRead, false)]
    [InlineData(PamPermissions.RequestsCreate, false)]
    [InlineData(PamPermissions.RequestsReadOwn, false)]
    public void AuthenticationAge_DeliveredOperations_HaveExplicitSensitivity(string permission, bool sensitive)
    {
        // Act / Assert
        Assert.Equal(sensitive, PamPermissionRoles.RequiresRecentAuthentication(permission));
    }

    [Fact]
    public void AuthenticationAge_UnknownOperation_CannotOptOutOfFreshness()
    {
        // Act / Assert
        Assert.Throws<ArgumentException>(() => PamPermissionRoles.RequiresRecentAuthentication("unknown.operation"));
    }

    [Theory]
    [InlineData("admin", true, true)]
    [InlineData("admin,user", true, true)]
    [InlineData("user", true, false)]
    [InlineData("approver", true, false)]
    [InlineData("user,approver", true, false)]
    [InlineData("Admin", true, false)]
    [InlineData("superadmin", true, false)]
    [InlineData("", true, false)]
    [InlineData("admin", false, false)]
    public async Task Authorize_ResourceManagementRead_UsesOnlyExplicitAuthenticatedAdmin(string roles, bool authenticated, bool allowed)
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var identity = new ClaimsIdentity(roles.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(role => new Claim(PamClaimTypes.Role, role)),
            authenticated ? "test" : null, "name", PamClaimTypes.Role);

        // Act
        var result = await authorization.AuthorizeAsync(new ClaimsPrincipal(identity), PamPermissions.ResourcesReadAll);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Theory]
    [InlineData("user", true)]
    [InlineData("admin,user", true)]
    [InlineData("approver,user", true)]
    [InlineData("admin", false)]
    [InlineData("approver", false)]
    [InlineData("User", false)]
    [InlineData("", false)]
    public async Task Authorize_OwnerRead_RequiresExplicitUserCapability(string roles, bool allowed)
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var identity = new ClaimsIdentity(roles.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(role => new Claim(PamClaimTypes.Role, role)), "test", "name", PamClaimTypes.Role);

        // Act
        var result = await authorization.AuthorizeAsync(new ClaimsPrincipal(identity), PamPermissions.RequestsReadOwn);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Theory]
    [InlineData("user", true)]
    [InlineData("admin,user", true)]
    [InlineData("approver,user", true)]
    [InlineData("admin", false)]
    [InlineData("approver", false)]
    [InlineData("", false)]
    public async Task Authorize_Submission_RequiresExplicitRequesterCapability(string roles, bool allowed)
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var identity = new ClaimsIdentity(roles.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(role => new Claim(PamClaimTypes.Role, role)), "test", "name", PamClaimTypes.Role);

        // Act
        var result = await authorization.AuthorizeAsync(new ClaimsPrincipal(identity), PamPermissions.RequestsCreate);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Theory]
    [InlineData("user", true)]
    [InlineData("approver", true)]
    [InlineData("user,approver", true)]
    [InlineData("admin", false)]
    [InlineData("superadmin", false)]
    [InlineData("User", false)]
    [InlineData("", false)]
    public async Task Authorize_ScopedRead_UsesExplicitOverlappingBundles(string roles, bool allowed)
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var identity = new ClaimsIdentity(roles.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(role => new Claim(PamClaimTypes.Role, role)), "test", "name", PamClaimTypes.Role);

        // Act
        var result = await authorization.AuthorizeAsync(new ClaimsPrincipal(identity), PamPermissions.ResourcesReadScoped);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Fact]
    public void Roles_UnknownPermission_HasNoImplicitBundle()
    {
        // Act / Assert
        Assert.Throws<ArgumentException>(() => PamPermissionRoles.For("requests.unknown"));
    }

    [Fact]
    public async Task Authorize_UnknownPermission_DoesNotFallBackToAuthenticatedAccess()
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System).AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(PamClaimTypes.Role, "admin")], "test"));

        // Act / Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => authorization.AuthorizeAsync(principal, "resources.unknown"));
    }
}
