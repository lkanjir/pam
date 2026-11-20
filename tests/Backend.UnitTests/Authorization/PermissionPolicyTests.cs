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
        using var services = new ServiceCollection().AddLogging().AddPamAuthorization().BuildServiceProvider();
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
        using var services = new ServiceCollection().AddLogging().AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var identity = new ClaimsIdentity(roles.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(role => new Claim(PamClaimTypes.Role, role)), "test", "name", PamClaimTypes.Role);

        // Act
        var result = await authorization.AuthorizeAsync(new ClaimsPrincipal(identity), PamPermissions.RequestsReadOwn);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Fact]
    public async Task Authorize_UnknownPermission_DoesNotFallBackToAuthenticatedAccess()
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddPamAuthorization().BuildServiceProvider();
        var authorization = services.GetRequiredService<IAuthorizationService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(PamClaimTypes.Role, "admin")], "test"));

        // Act / Assert
        await Assert.ThrowsAsync<InvalidOperationException>(() => authorization.AuthorizeAsync(principal, "resources.unknown"));
    }
}
