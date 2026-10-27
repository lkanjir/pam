using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using System.Net;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class CookieAccessTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Authenticate_WhenAccessChanges_RevokesSession(bool rolesChanged)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var principalId = await SeedPrincipalAsync(database);
        var clock = new TestTimeProvider();
        await using var server = await CreateSessionServerAsync(database, clock, principalId, redis.Connection);
        using var client = server.GetTestClient();
        using var login = await client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        UpdateCookie(client, login);
        var hash = await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).SingleAsync();
        if (rolesChanged)
        {
            await database.Context.Database.ExecuteSqlRawAsync("""
                INSERT INTO pam_roles (code, description, created_by_principal_id)
                SELECT 'admin', 'Administrator', id FROM principals;
                INSERT INTO pam_role_assignments (principal_id, role_id, assigned_by_principal_id)
                SELECT p.id, r.id, p.id FROM principals p CROSS JOIN pam_roles r;
                """);
        }
        else
            await database.Context.Database.ExecuteSqlRawAsync("UPDATE principals SET is_enabled = false");
        clock.Now = clock.Now.AddMinutes(16); // Also exercise a pending sliding renewal.

        // Act
        using var response = await client.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
        Assert.Equal("access_changed", await database.Context.AuthenticationSessionLedgers
            .Select(s => s.EndReason).SingleAsync());
    }
}
