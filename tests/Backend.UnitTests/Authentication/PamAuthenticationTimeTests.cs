using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Api.Authentication;
using Application.Identity;
using FakeItEasy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;

namespace Backend.UnitTests.Authentication;

public sealed class PamAuthenticationTimeTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unknown")]
    [InlineData("-1")]
    [InlineData("253402300800")]
    [InlineData("9223372036854775808")]
    [InlineData("1792756800.5")]
    [InlineData(" 1792756800")]
    public void Read_MissingOrMalformedTime_DoesNotInventAuthenticationTime(string? value)
    {
        // Arrange
        var identity = new ClaimsIdentity(value is null ? [] : [new Claim(PamClaimTypes.AuthenticationTime, value)], "test");

        // Act
        var result = PamAuthenticationTime.Read(new ClaimsPrincipal(identity));

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public void Read_DuplicateTimes_DoesNotSelectAnArbitraryValue()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
        [
            new Claim(PamClaimTypes.AuthenticationTime, "0"),
            new Claim(PamClaimTypes.AuthenticationTime, "1792756800")
        ], "test"));

        // Act / Assert
        Assert.Null(PamAuthenticationTime.Read(principal));
    }

    [Fact]
    public void Read_OnlyRawProtocolTime_DoesNotTreatItAsNormalizedPamIdentity()
    {
        // Arrange
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim("auth_time", "1792756800")], "test"));

        // Act / Assert
        Assert.Null(PamAuthenticationTime.Read(principal));
    }

    [Fact]
    public async Task TokenValidated_ProtocolTime_PreservesOriginalTimeAndDropsUntrustedPamClaims()
    {
        // Arrange
        var reader = A.Fake<IPrincipalIdentityReader>();
        var principal = new PrincipalIdentity(42, Guid.NewGuid(), "Ana", true, ["user"]);
        A.CallTo(() => reader.FindAsync("issuer", "ana", A<CancellationToken>._)).Returns(principal);
        var events = OidcEventsFixture.Create(reader, A.Fake<IProblemDetailsService>());
        var context = new TokenValidatedContext(new DefaultHttpContext(),
            new AuthenticationScheme("oidc", null, typeof(OpenIdConnectHandler)), new OpenIdConnectOptions(),
            new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "ana"),
                new Claim("auth_time", "1792756800"),
                new Claim(PamClaimTypes.AuthenticationTime, "253402300799"),
                new Claim(PamClaimTypes.Role, "admin")
            ], "oidc")), new AuthenticationProperties())
        {
            SecurityToken = new JwtSecurityToken(issuer: "issuer")
        };

        // Act
        await events.TokenValidated(context);

        // Assert
        Assert.NotNull(context.Principal);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1792756800), PamAuthenticationTime.Read(context.Principal));
        Assert.Equal("1792756800", context.Principal.FindFirst(PamClaimTypes.AuthenticationTime)?.Value);
        Assert.True(context.Principal.IsInRole("user"));
        Assert.False(context.Principal.IsInRole("admin"));
        Assert.Null(context.Principal.FindFirst("auth_time"));
        Assert.True(PamClaims.TryRead(context.Principal, out var identity));
        Assert.Equal(principal.PublicId, identity.PublicId);
    }
}
