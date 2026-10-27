using System.Security.Claims;
using Api.Authentication;
using Application.Identity;
using Backend.Tests.Support;

namespace Backend.UnitTests.Authentication;

public sealed class PamClaimsTests
{
    [Fact]
    public void Create_PreservesFrameworkNameAndRoleSemanticsAndIdentityData()
    {
        var principal = new PrincipalIdentity(42, Guid.NewGuid(), "Ana Horvat", true, ["admin", "reader"]);

        var claims = PamClaims.Create(principal, "https://issuer.example", "ana", "idp-session");

        Assert.Equal("Ana Horvat", claims.Identity!.Name);
        Assert.True(claims.Identity.IsAuthenticated);
        Assert.True(claims.IsInRole("admin"));
        Assert.True(claims.IsInRole("reader"));
        Assert.Equal("42", claims.FindFirst(ClaimTypes.NameIdentifier)?.Value);
        Assert.True(PamClaims.TryRead(claims, out var identity));
        Assert.Equal(principal.Id, identity.Id);
        Assert.Equal(principal.PublicId, identity.PublicId);
        Assert.Equal(principal.DisplayName, identity.DisplayName);
        Assert.Equal("https://issuer.example", identity.Issuer);
        Assert.Equal("ana", identity.Subject);
        Assert.Equal(principal.Roles, identity.Roles);
        Assert.Equal("idp-session", identity.IdpSessionId);
    }

    [Fact]
    public void TryRead_AcceptsExistingTicketSchemaWithoutOptionalSessionIdOrRoles()
    {
        var claims = SessionTestData.Ticket(DateTimeOffset.UtcNow).Principal;
        var source = (ClaimsIdentity)claims.Identity!;
        foreach (var claim in source.FindAll("sid").ToArray()) source.RemoveClaim(claim);

        Assert.True(PamClaims.TryRead(claims, out var identity));
        Assert.Equal("Ana Horvat", identity.DisplayName);
        Assert.Null(identity.IdpSessionId);
        Assert.Empty(identity.Roles);
    }

    [Theory]
    [InlineData(ClaimTypes.NameIdentifier, null)]
    [InlineData(ClaimTypes.NameIdentifier, "0")]
    [InlineData(ClaimTypes.NameIdentifier, "-1")]
    [InlineData(ClaimTypes.NameIdentifier, "invalid")]
    [InlineData(ClaimTypes.NameIdentifier, "9223372036854775808")]
    [InlineData("pam_public_id", null)]
    [InlineData("pam_public_id", "invalid")]
    [InlineData("pam_issuer", null)]
    [InlineData("pam_issuer", " ")]
    [InlineData("sub", null)]
    [InlineData("sub", " ")]
    [InlineData("name", null)]
    public void TryRead_RejectsIncompleteOrMalformedIdentity(string type, string? value)
    {
        var claims = SessionTestData.Ticket(DateTimeOffset.UtcNow).Principal;
        var source = (ClaimsIdentity)claims.Identity!;
        source.RemoveClaim(source.FindFirst(type));
        if (value is not null) source.AddClaim(new Claim(type, value));

        Assert.False(PamClaims.TryRead(claims, out var identity));
        Assert.Null(identity);
    }
}
