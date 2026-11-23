using System.Globalization;
using System.Security.Claims;
using Api.Authentication;
using Api.Authorization;
using Application.Authorization;
using Backend.Tests.Support;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Backend.UnitTests.Authorization;

public sealed class RecentAuthenticationTests
{
    [Theory]
    [InlineData(-6000000001L, false)]
    [InlineData(-6000000000L, true)]
    [InlineData(-5999999999L, true)]
    [InlineData(0L, true)]
    [InlineData(599999999L, true)]
    [InlineData(600000000L, true)]
    [InlineData(600000001L, false)]
    public void Evaluate_AgeAndFutureSkewBoundaries_EnforceExactWindow(long offsetTicks, bool allowed)
    {
        // Arrange
        var now = new TestTimeProvider().Now;
        var authenticatedAt = now.AddTicks(offsetTicks);

        // Act / Assert
        Assert.Equal(allowed, RecentAuthentication.IsSatisfied(authenticatedAt, now));
    }

    [Fact]
    public void Evaluate_UnknownAuthenticationTime_DeniesFreshness()
    {
        // Act / Assert
        Assert.False(RecentAuthentication.IsSatisfied(null, new TestTimeProvider().Now));
    }

    [Theory]
    [InlineData(600, true, true)]
    [InlineData(601, true, false)]
    [InlineData(0, false, false)]
    public async Task Authorize_RecentPolicy_RequiresFreshTimeAndAuthentication(int ageSeconds, bool authenticated, bool allowed)
    {
        // Arrange
        var clock = new TestTimeProvider();
        using var services = new ServiceCollection().AddLogging().AddSingleton<TimeProvider>(clock)
            .AddPamAuthorization().BuildServiceProvider();
        var identity = new ClaimsIdentity(
            [new Claim(PamClaimTypes.AuthenticationTime,
                clock.Now.AddSeconds(-ageSeconds).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture))],
            authenticated ? "test" : null);

        // Act
        var result = await services.GetRequiredService<IAuthorizationService>()
            .AuthorizeAsync(new ClaimsPrincipal(identity), PamPolicies.RecentAuthentication);

        // Assert
        Assert.Equal(allowed, result.Succeeded);
    }
}
