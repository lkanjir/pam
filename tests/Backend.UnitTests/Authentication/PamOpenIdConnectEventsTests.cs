using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Api.Authentication;
using Application.Identity;
using FakeItEasy;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Backend.UnitTests.Authentication;

public sealed class PamOpenIdConnectEventsTests
{
    private static readonly AuthenticationScheme Scheme = new("oidc", null, typeof(OpenIdConnectHandler));

    [Theory]
    [InlineData("", "ana")]
    [InlineData("issuer", null)]
    [InlineData("issuer", " ")]
    public async Task TokenValidated_MissingIdentity_StopsLoginBeforePrincipalLookup(string issuer, string? subject)
    {
        // Arrange
        var reader = A.Fake<IPrincipalIdentityReader>();
        var problems = A.Fake<IProblemDetailsService>();
        var events = new PamOpenIdConnectEvents(reader, problems, NullLogger<PamOpenIdConnectEvents>.Instance);
        var claims = subject is null ? Array.Empty<Claim>() : [new Claim("sub", subject)];
        var context = new TokenValidatedContext(new DefaultHttpContext(), Scheme, new OpenIdConnectOptions(),
            new ClaimsPrincipal(new ClaimsIdentity(claims)), new AuthenticationProperties())
        {
            SecurityToken = new JwtSecurityToken(issuer: issuer)
        };

        // Act
        await events.TokenValidated(context);

        // Assert
        Assert.True(context.Result?.Handled);
        A.CallTo(() => problems.WriteAsync(A<ProblemDetailsContext>.That.Matches(p => p.ProblemDetails.Status == 401)))
            .MustHaveHappenedOnceExactly();
        A.CallTo(() => reader.FindAsync(A<string>._, A<string>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task RemoteFailure_AbortedRequest_DoesNotWriteResponse()
    {
        // Arrange
        var problems = A.Fake<IProblemDetailsService>();
        var events = new PamOpenIdConnectEvents(A.Fake<IPrincipalIdentityReader>(), problems,
            NullLogger<PamOpenIdConnectEvents>.Instance);
        var http = new DefaultHttpContext { RequestAborted = new CancellationToken(true) };
        var context = new RemoteFailureContext(http, Scheme, new OpenIdConnectOptions(),
            new OperationCanceledException());

        // Act
        await events.RemoteFailure(context);

        // Assert
        Assert.True(context.Result?.Handled);
        A.CallTo(() => problems.WriteAsync(A<ProblemDetailsContext>._)).MustNotHaveHappened();
    }
}
