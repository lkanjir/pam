using System.Net;
using System.Net.Http.Json;
using Api.Authentication;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class LogoutPipelineTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task Logout_WithoutAuthentication_ReturnsUnauthorized()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        await using var app = await CreateSessionServerAsync(database, new TestTimeProvider(), principalId, redis.Connection);
        using var client = app.GetTestClient();

        // Act
        using var response = await client.PostAsync("/api/auth/logout", null);

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(await database.Context.AuditEvents.ToListAsync());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid-token")]
    public async Task Logout_WithoutValidAntiforgeryToken_LeavesSessionActive(string? token)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        await using var app = await CreateSessionServerAsync(database, new TestTimeProvider(), principalId, redis.Connection);
        using var client = app.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        using var antiforgery = await client.GetAsync("/api/auth/antiforgery");
        antiforgery.EnsureSuccessStatusCode();
        UpdateCookie(client, antiforgery);
        if (token is not null) client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token);

        // Act
        using var response = await client.PostAsync("/api/auth/logout", null);

        // Assert
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Null(await database.Context.AuthenticationSessionLedgers.Select(s => s.EndedAt).SingleAsync());
        Assert.False(await database.Context.AuditEvents.AnyAsync(e => e.EventType == "authentication.session.ended"));
        using var current = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, current.StatusCode);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Logout_WithValidToken_RevokesSessionEvenIfAuditFails(bool auditFails)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var app = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = app.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        var oldCookie = client.DefaultRequestHeaders.GetValues("Cookie").Single();
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();
        using var antiforgery = await client.GetAsync("/api/auth/antiforgery");
        antiforgery.EnsureSuccessStatusCode();
        var token = await antiforgery.Content.ReadFromJsonAsync<AntiforgeryTokenResponse>();
        UpdateCookie(client, antiforgery);
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", token!.RequestToken);
        if (auditFails) await RejectLogoutAuditAsync(database);
        clock.Now = clock.Now.AddMinutes(16); // Logout must suppress pending sliding renewal.

        // Act
        using var response = await client.PostAsync("/api/auth/logout", null);

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), value => value.StartsWith("pam.session=;"));
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
        if (!auditFails)
        {
            Assert.Equal("logout", await database.Context.AuthenticationSessionLedgers.Select(s => s.EndReason).SingleAsync());
            Assert.Equal(1, await database.Context.AuditEvents.CountAsync(e =>
                e.EventType == "authentication.session.ended" && e.ReasonCode == "logout"));
        }
        client.DefaultRequestHeaders.Remove("Cookie");
        client.DefaultRequestHeaders.Add("Cookie", oldCookie);
        using var replay = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }
}
