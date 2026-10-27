using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class CookieLifetimeTests(PostgresFixture postgres, RedisFixture redis)
{
    [Fact]
    public async Task RetrieveAsync_WithLegacyTicketWithoutAbsoluteDeadline_RejectsSession()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var clock = new TestTimeProvider();
        await using var services = CreateServices(database, clock, redis.Connection);
        var rawStore = services.GetRequiredService<ISessionTicketStore>();
        var id = await rawStore.StoreAsync(SessionTestData.Ticket(clock.Now));
        var store = services.GetRequiredService<Microsoft.AspNetCore.Authentication.Cookies.ITicketStore>();

        // Act
        var ticket = await store.RetrieveAsync(id);

        // Assert
        Assert.Null(ticket);
    }

    [Theory]
    [InlineData(479, HttpStatusCode.OK)]
    [InlineData(480, HttpStatusCode.Unauthorized)]
    public async Task Authenticate_WithContinuousSlidingRenewal_EnforcesAbsoluteDeadline(
        int elapsedMinutes, HttpStatusCode expectedStatus)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        var startedAt = clock.Now;
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        for (var minute = 16; minute < elapsedMinutes; minute += 16)
        {
            clock.Now = startedAt.AddMinutes(minute);
            using var activeRequest = await client.GetAsync("/api/me");
            activeRequest.EnsureSuccessStatusCode();
            UpdateCookie(client, activeRequest);
        }
        clock.Now = startedAt.AddMinutes(elapsedMinutes);

        // Act
        using var response = await client.GetAsync("/api/me");

        // Assert
        Assert.Equal(expectedStatus, response.StatusCode);
    }

    [Fact]
    public async Task SlidingRenewal_NearAbsoluteDeadline_CapsLedgerExpiry()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        var startedAt = clock.Now;
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        for (var minute = 16; minute <= 448; minute += 16)
        {
            clock.Now = startedAt.AddMinutes(minute);
            using var activeRequest = await client.GetAsync("/api/me");
            activeRequest.EnsureSuccessStatusCode();
            UpdateCookie(client, activeRequest);
        }
        clock.Now = startedAt.AddMinutes(464);

        // Act
        using var response = await client.GetAsync("/api/me");
        response.EnsureSuccessStatusCode();

        // Assert
        Assert.Equal(startedAt.AddHours(8).UtcDateTime, await database.Context.AuthenticationSessionLedgers
            .Select(s => s.ExpectedExpiresAt).SingleAsync());
    }

    [Fact]
    public async Task SlidingRenewal_NearAbsoluteDeadline_CapsRedisTtl()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        var startedAt = clock.Now;
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        for (var minute = 16; minute <= 448; minute += 16)
        {
            clock.Now = startedAt.AddMinutes(minute);
            using var activeRequest = await client.GetAsync("/api/me");
            activeRequest.EnsureSuccessStatusCode();
            UpdateCookie(client, activeRequest);
        }
        clock.Now = startedAt.AddMinutes(464);
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();

        // Act
        using var response = await client.GetAsync("/api/me");
        response.EnsureSuccessStatusCode();

        // Assert
        var ttl = await redis.Connection.GetDatabase().KeyTimeToLiveAsync("pam:session:" + hash);
        Assert.InRange(ttl ?? TimeSpan.Zero, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(16));
    }
}
