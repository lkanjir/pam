using System.Net;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using static Backend.IntegrationTests.Sessions.SessionTestHost;

namespace Backend.IntegrationTests.Sessions;

[Collection(StorageCollection4.Name)]
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
        {
            await database.Context.Database.ExecuteSqlRawAsync("UPDATE principals SET is_enabled = false");
        }

        clock.Now = clock.Now.AddMinutes(16); // Also exercise a pending sliding renewal.

        // Act
        using var response = await client.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
        Assert.Equal("access_changed", await database.Context.AuthenticationSessionLedgers
            .Select(s => s.EndReason).SingleAsync());
    }

    [Theory]
    [InlineData("public-id")]
    [InlineData("issuer")]
    [InlineData("subject")]
    public async Task Authenticate_CurrentIdentityMappingChanges_RevokesSessionBeforeRenewal(string changedField)
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
        string hash = await database.Context.AuthenticationSessionLedgers.Select(value => value.SessionIdHash).SingleAsync();
        _ = changedField switch
        {
            "public-id" => await database.Context.Principals.ExecuteUpdateAsync(update => update.SetProperty(value => value.PublicId, Guid.NewGuid())),
            "issuer" => await database.Context.Principals.ExecuteUpdateAsync(update => update.SetProperty(value => value.Issuer, "https://other.example/realms/pam")),
            _ => await database.Context.Principals.ExecuteUpdateAsync(update => update.SetProperty(value => value.Subject, "other-person"))
        };
        clock.Now = clock.Now.AddMinutes(16);

        // Act
        using var response = await client.GetAsync("/api/me");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(await redis.Connection.GetDatabase().KeyExistsAsync("pam:session:" + hash));
        var session = await database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal("access_changed", session.EndReason);
        Assert.Equal(clock.Now.UtcDateTime, session.EndedAt);
        Assert.Equal(1, await database.Context.AuditEvents.CountAsync(value => value.EventType == "authentication.session.ended"));
    }

}
