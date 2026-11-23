using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Backend.IntegrationTests.Fixtures;

public sealed class PostgresFixtureTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Fact]
    public async Task CreateDatabase_ConcurrentCalls_ReturnIndependentMigratedDatabases()
    {
        // Arrange / Act
        var databases = await Task.WhenAll(postgres.CreateDatabaseAsync(), postgres.CreateDatabaseAsync());
        await using var first = databases[0];
        await using var second = databases[1];

        // Assert
        Assert.NotEqual(first.Context.Database.GetDbConnection().Database, second.Context.Database.GetDbConnection().Database);
        var migrations = first.Context.Database.GetMigrations().ToArray();
        Assert.NotEmpty(migrations);
        Assert.Equal(migrations, await first.Context.Database.GetAppliedMigrationsAsync());
        Assert.Equal(migrations, await second.Context.Database.GetAppliedMigrationsAsync());
        Assert.False(await first.Context.Principals.AnyAsync());
        Assert.False(await second.Context.Principals.AnyAsync());

        first.Context.Principals.Add(PrincipalMapping("same-subject"));
        await first.Context.SaveChangesAsync();
        Assert.False(await second.Context.Principals.AnyAsync());
        second.Context.Principals.Add(PrincipalMapping("same-subject"));
        await second.Context.SaveChangesAsync();
        Assert.Equal(1, await first.Context.Principals.CountAsync());
        Assert.Equal(1, await second.Context.Principals.CountAsync());
    }

    [Fact]
    public async Task CreateDatabase_ModifiedClone_DoesNotLeakDataOrSchemaIntoLaterClone()
    {
        // Arrange
        await using var first = await postgres.CreateDatabaseAsync();
        first.Context.Principals.Add(PrincipalMapping("first-only"));
        await first.Context.SaveChangesAsync();
        await first.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE principals ADD CONSTRAINT fixture_reject_subject CHECK (subject <> 'blocked')");

        // Act
        await using var second = await postgres.CreateDatabaseAsync();

        // Assert
        Assert.False(await second.Context.Principals.AnyAsync());
        second.Context.Principals.Add(PrincipalMapping("blocked"));
        await second.Context.SaveChangesAsync();
        Assert.Equal("blocked", await second.Context.Principals.Select(principal => principal.Subject).SingleAsync());
        first.Context.Principals.Add(PrincipalMapping("blocked"));
        var error = await Assert.ThrowsAsync<DbUpdateException>(() => first.Context.SaveChangesAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, Assert.IsType<PostgresException>(error.InnerException).SqlState);
        Assert.Equal("first-only", await first.Context.Principals.Select(principal => principal.Subject).SingleAsync());
    }

    private static Principal PrincipalMapping(string subject) =>
        Principal.CreateMapping("https://fixture.example", subject, "Fixture principal", DateTimeOffset.UnixEpoch);
}
