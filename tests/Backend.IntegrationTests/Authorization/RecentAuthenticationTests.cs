using System.Net;
using System.Text.Json;
using Api.Authorization;
using Application.Authorization;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection3.Name)]
public sealed class RecentAuthenticationTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData("admin", 0, 200, false)]
    [InlineData("admin", 600, 200, false)]
    [InlineData("admin", 601, 403, true)]
    [InlineData("user", 0, 403, false)]
    [InlineData("user", 601, 403, false)]
    public async Task Get_RecentPolicy_ReportsFreshnessOnlyAfterCapabilityIsSatisfied(string role, int ageSeconds, int status, bool recentCode)
    {
        // Arrange
        await using var test = await CreateAsync(role);
        await test.AuthenticateAsync(includeResourceVersion: false);
        test.Clock.Now = test.Clock.Now.AddSeconds(ageSeconds);

        // Act
        using var response = await test.Client.GetAsync("/api/recent-check");

        // Assert
        Assert.Equal(status, (int)response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Null(response.Headers.Location);
        if (status == 403)
        {
            using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            bool hasCode = problem.RootElement.TryGetProperty("code", out var code);
            Assert.Equal(recentCode, hasCode);
            if (recentCode)
            {
                Assert.Equal("recent_auth_required", code.GetString());
            }
        }
    }

    [Fact]
    public async Task Get_TicketWithoutAuthenticationTime_RequiresReauthenticationDespiteFreshCookie()
    {
        // Arrange
        await using var test = await CreateAsync("admin");
        await test.AuthenticateAsync(includeResourceVersion: false, includeAuthenticationTime: false);

        // Act
        using var response = await test.Client.GetAsync("/api/recent-check");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("recent_auth_required", problem.RootElement.GetProperty("code").GetString());
        using var profile = await test.Client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
    }

    [Fact]
    public async Task Get_NoSession_ReturnsUnauthorizedWithoutIdpRedirect()
    {
        // Arrange
        await using var test = await CreateAsync("admin");

        // Act
        using var response = await test.Client.GetAsync("/api/recent-check");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(response.Headers.Location);
    }

    [Fact]
    public async Task Get_AfterSlidingRenewal_DoesNotRefreshAuthenticationAge()
    {
        // Arrange
        await using var test = await CreateAsync("admin");
        await test.AuthenticateAsync(includeResourceVersion: false);
        var initial = test.Clock.Now;
        test.Clock.Now = initial.AddMinutes(16);
        using var profile = await test.Client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, profile.StatusCode);
        Assert.Contains(profile.Headers.GetValues("Set-Cookie"), cookie => cookie.StartsWith("pam.session=", StringComparison.Ordinal));
        SessionTestHost.UpdateCookie(test.Client, profile);
        Assert.Equal(initial.AddMinutes(46).UtcDateTime,
            await test.Database.Context.AuthenticationSessionLedgers.Select(s => s.ExpectedExpiresAt).SingleAsync());

        // Act
        using var response = await test.Client.GetAsync("/api/recent-check");

        // Assert
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        using var problem = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("recent_auth_required", problem.RootElement.GetProperty("code").GetString());
    }

    private Task<ResourceTestContext> CreateAsync(string role) => ResourceTestContext.CreateAsync(postgres, redis.Connection,
        configure: app => app.MapGet("/api/recent-check", () => TypedResults.Ok())
            .RequireAuthorization(PamPermissions.ResourcesReadAll, PamPolicies.RecentAuthentication), roles: [role]);
}
