using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql;

namespace Backend.IntegrationTests.Migrations;

public sealed class ProductionDatabaseTests
{
    [Fact]
    public async Task Apply_ReviewedSqlTwice_CreatesCurrentSchemaWithoutMigrator()
    {
        // Arrange
        await using var database = await MigrationDatabase.StartAsync(bootstrap: false);
        await using var context = database.Context(admin: true);
        string sql = context.GetService<IMigrator>().GenerateScript(options: MigrationsSqlGenerationOptions.Idempotent);

        // Act
        await database.ExecuteAdminAsync(sql);
        await database.ExecuteAdminAsync(sql);

        // Assert
        var expected = context.Database.GetMigrations().ToArray();
        Assert.NotEmpty(expected);
        Assert.Equal(expected, await context.Database.GetAppliedMigrationsAsync());
    }

    [Fact]
    public async Task Apply_RestrictedApiRole_CanCreateReadUpdateAndDeleteApplicationData()
    {
        // Arrange
        await using var database = await ProductionAsync();
        await using var connection = new NpgsqlConnection(database.AppConnection);
        await connection.OpenAsync();

        // Act
        await using var command = new NpgsqlCommand("""
            INSERT INTO principals (issuer, subject, display_name, is_enabled)
                VALUES ('test-issuer', 'test-subject', 'Before', true);
            UPDATE principals SET display_name = 'After' WHERE subject = 'test-subject';
            SELECT display_name FROM principals WHERE subject = 'test-subject';
            """, connection);
        var name = await command.ExecuteScalarAsync();
        await using var delete = new NpgsqlCommand("DELETE FROM principals WHERE subject = 'test-subject'", connection);
        int removed = await delete.ExecuteNonQueryAsync();

        // Assert
        Assert.Equal("After", name);
        Assert.Equal(1, removed);
    }

    [Fact]
    public async Task Apply_RestrictedApiRole_CanAppendAndReadAuditEvents()
    {
        // Arrange
        await using var database = await ProductionAsync();
        await using var connection = new NpgsqlConnection(database.AppConnection);
        await connection.OpenAsync();

        // Act
        await using var command = new NpgsqlCommand("""
            INSERT INTO audit_events (event_type, actor_kind, correlation_id, source)
                VALUES ('test-event', 'system', 'test-correlation', 'test');
            SELECT event_type FROM audit_events WHERE correlation_id = 'test-correlation';
            """, connection);
        var eventType = await command.ExecuteScalarAsync();

        // Assert
        Assert.Equal("test-event", eventType);
    }

    [Theory]
    [InlineData("CREATE TABLE forbidden_table (id integer)")]
    [InlineData("CREATE SCHEMA forbidden_schema")]
    [InlineData("CREATE DATABASE forbidden_database")]
    [InlineData("ALTER TABLE principals ADD COLUMN forbidden text")]
    [InlineData("DROP TABLE audit_events")]
    [InlineData("UPDATE audit_events SET event_type = 'rewritten'")]
    [InlineData("DELETE FROM audit_events")]
    [InlineData("TRUNCATE audit_events")]
    [InlineData("SELECT * FROM public.\"__EFMigrationsHistory\"")]
    public async Task Apply_RestrictedApiRole_DeniesSchemaAndProtectedTableAccess(string sql)
    {
        // Arrange
        await using var database = await ProductionAsync();
        await using var connection = new NpgsqlConnection(database.AppConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);

        // Act
        var exception = await Assert.ThrowsAsync<PostgresException>(() => command.ExecuteNonQueryAsync());

        // Assert
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, exception.SqlState);
    }

    [Fact]
    public async Task Apply_DevelopmentOwner_RefusesToPretendRuntimeRoleIsRestricted()
    {
        // Arrange
        await using var database = await MigrationDatabase.StartAsync();
        Assert.Equal((0, string.Empty), await database.RunAsync());

        // Act
        var result = await database.ApplyProductionPermissionsAsync();

        // Assert
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("must not own", result.Error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Apply_InheritedSchemaCreation_RejectsBypassPrivileges()
    {
        // Arrange
        await using var database = await ProductionAsync();
        await database.ExecuteAdminAsync("""
            CREATE ROLE schema_writers;
            GRANT CREATE ON SCHEMA public TO schema_writers;
            GRANT schema_writers TO api_development;
            """);

        // Act
        var result = await database.ApplyProductionPermissionsAsync();

        // Assert
        Assert.NotEqual(0, result.ExitCode);
        Assert.Contains("bypass the API restrictions", result.Error, StringComparison.Ordinal);
    }

    private static async Task<MigrationDatabase> ProductionAsync()
    {
        var database = await MigrationDatabase.StartAsync(bootstrap: false);
        try
        {
            await using var context = database.Context(admin: true);
            string sql = context.GetService<IMigrator>().GenerateScript(options: MigrationsSqlGenerationOptions.Idempotent);
            await database.ExecuteAdminAsync(sql);
            await database.ExecuteAdminAsync("CREATE ROLE api_development LOGIN PASSWORD 'isolated-test-password'");
            Assert.Equal((0L, string.Empty), await database.ApplyProductionPermissionsAsync());
            Assert.Equal((0L, string.Empty), await database.ApplyProductionPermissionsAsync());
            return database;
        }
        catch
        {
            await database.DisposeAsync();
            throw;
        }
    }
}
