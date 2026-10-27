using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class CookieSignInTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SignIn_WithDefaultProperties_UsesConfiguredCookieLifetime(bool persistent)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();

        // Act
        using var response = await client.GetAsync($"/login?persistent={persistent}");
        response.EnsureSuccessStatusCode();

        // Assert
        var cookie = Microsoft.Net.Http.Headers.SetCookieHeaderValue.Parse(
            response.Headers.GetValues("Set-Cookie").Single());
        Assert.Equal("pam.session", cookie.Name.ToString());
        Assert.True(cookie.HttpOnly);
        Assert.Equal(Microsoft.Net.Http.Headers.SameSiteMode.Strict, cookie.SameSite);
        Assert.Equal("/", cookie.Path.ToString());
        Assert.Equal(persistent ? clock.Now.AddMinutes(30) : (DateTimeOffset?)null, cookie.Expires);
        Assert.Equal(clock.Now.AddMinutes(30).UtcDateTime,
            await database.Context.AuthenticationSessionLedgers.Select(s => s.ExpectedExpiresAt).SingleAsync());
    }

    [Fact]
    public async Task SignIn_WithRedirect_ReturnsUsableCookieAndNoStoreHeaders()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();

        // Act
        using var response = await client.GetAsync("/login?redirect=true");

        // Assert
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/api/me", response.Headers.Location?.OriginalString);
        Assert.True(response.Headers.CacheControl?.NoStore);
        UpdateCookie(client, response);
        using var authenticated = await client.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
    }

    [Fact]
    public async Task SignInAsync_WhenPersistenceSucceeds_IssuesSessionCookie()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock, redis.Connection);
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        var ticket = SessionTestData.Ticket(clock.Now, principalId);

        // Act
        await context.SignInAsync("Cookies", ticket.Principal, ticket.Properties);

        // Assert
        Assert.Contains(context.Response.Headers.SetCookie, value => value!.StartsWith("pam.session="));
    }

    [Fact]
    public async Task SignInAsync_WhenAuditPersistenceFails_DoesNotIssueCookie()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        await database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_test_event CHECK (event_type <> 'authentication.session.started')");
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock, redis.Connection);
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        var ticket = SessionTestData.Ticket(clock.Now, principalId);

        // Act
        await Assert.ThrowsAsync<DbUpdateException>(() => context.SignInAsync("Cookies", ticket.Principal, ticket.Properties));

        // Assert
        Assert.Equal(0, context.Response.Headers.SetCookie.Count);
    }
}
