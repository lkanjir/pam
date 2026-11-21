using System.Security.Claims;
using Api.Authentication;
using Api.Authorization;
using Application.Authorization;
using Application.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Backend.UnitTests.Authorization;

public sealed class BootstrapPolicyTests
{
    [Theory]
    [InlineData(PamPermissions.BootstrapRead, true)]
    [InlineData(PamPermissions.PrincipalsRead, true)]
    [InlineData(PamPermissions.PrincipalsManage, true)]
    [InlineData(PamPermissions.RolesRead, true)]
    [InlineData(PamPermissions.RolesAssign, true)]
    [InlineData(PamPermissions.ResourcesReadAll, false)]
    [InlineData(PamPermissions.ResourcesReadScoped, false)]
    [InlineData(PamPermissions.ResourcesManage, false)]
    [InlineData(PamPermissions.RequestsReadOwn, false)]
    [InlineData(PamPermissions.RequestsCreate, false)]
    [InlineData(PamPermissions.ResourceAccessRead, false)]
    [InlineData(PamPermissions.ResourceAccessAssign, false)]
    [InlineData(PamPermissions.EligibilityRead, false)]
    [InlineData(PamPermissions.EligibilityAssign, false)]
    [InlineData(PamPermissions.ApprovalAuthorityRead, false)]
    [InlineData(PamPermissions.ApprovalAuthorityAssign, false)]
    public async Task Authorize_BootstrapWithEveryBundle_OnlyAllowsInstallationOperations(string permission, bool allowed)
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System)
            .AddPamAuthorization().BuildServiceProvider();
        var identity = new PrincipalIdentity(1, Guid.NewGuid(), "Installer", true, ["admin", "user", "approver"])
        { IsBootstrap = true };
        var principal = PamClaims.Create(identity, "issuer", "subject", null);

        // Act
        var result = await services.GetRequiredService<IAuthorizationService>().AuthorizeAsync(principal, permission);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Authorize_PermanentAdministratorBoundary_RejectsTemporaryIdentity(bool bootstrap, bool allowed)
    {
        // Arrange
        using var services = new ServiceCollection().AddLogging().AddSingleton(TimeProvider.System)
            .AddPamAuthorization().BuildServiceProvider();
        var principal = PamClaims.Create(new PrincipalIdentity(1, Guid.NewGuid(), "Admin", true, ["admin"])
        { IsBootstrap = bootstrap }, "issuer", "subject", null);

        // Act
        var result = await services.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(principal, PamPolicies.PermanentAdministrator);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Claims_IdentityKind_RoundTripsThroughPrivateClaims(bool bootstrap)
    {
        // Arrange
        var principal = new PrincipalIdentity(1, Guid.NewGuid(), "Admin", true, ["admin"]) { IsBootstrap = bootstrap };

        // Act
        var claims = PamClaims.Create(principal, "issuer", "subject", null);
        bool parsed = PamClaims.TryRead(claims, out var identity);

        // Assert
        Assert.True(parsed);
        Assert.NotNull(identity);
        Assert.Equal(bootstrap, identity.IsBootstrap);
        Assert.Equal(bootstrap ? 1 : 0, claims.FindAll(PamClaimTypes.Bootstrap).Count());
    }

    [Theory]
    [InlineData("false", false)]
    [InlineData("True", false)]
    [InlineData("", false)]
    [InlineData("true", true)]
    public void Claims_InvalidOrDuplicateBootstrapFlag_RejectsIdentity(string value, bool duplicate)
    {
        // Arrange
        var principal = PamClaims.Create(new PrincipalIdentity(1, Guid.NewGuid(), "Admin", true, []), "issuer", "subject", null);
        var claims = Assert.IsType<ClaimsIdentity>(principal.Identity);
        claims.AddClaim(new Claim(PamClaimTypes.Bootstrap, value));
        if (duplicate)
        {
            claims.AddClaim(new Claim(PamClaimTypes.Bootstrap, "true"));
        }

        // Act / Assert
        Assert.False(PamClaims.TryRead(principal, out var identity));
        Assert.Null(identity);
    }
}
