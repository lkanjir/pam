using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Backend.IntegrationTests.Migrations;

public sealed class DevelopmentDatabaseTests
{
    [Fact]
    public async Task Run_SharedAppConnection_MigratesAndRetainsSchemaPermissions()
    {
        // Arrange
        await using var database = await MigrationDatabase.StartAsync();

        // Act
        var result = await database.RunAsync();

        // Assert
        Assert.Equal((0, string.Empty), result);
        await using var context = database.Context();
        var expected = context.Database.GetMigrations().ToArray();
        Assert.NotEmpty(expected);
        Assert.Equal(expected, await context.Database.GetAppliedMigrationsAsync());
        await using var connection = new NpgsqlConnection(database.AppConnection);
        await connection.OpenAsync();
        await using var permissions = new NpgsqlCommand("""
            SELECT has_schema_privilege(current_user, 'public', 'CREATE')
               AND has_table_privilege(current_user, 'public.audit_events', 'UPDATE')
               AND has_table_privilege(current_user, 'public.audit_events', 'DELETE')
               AND has_table_privilege(current_user, 'public."__EFMigrationsHistory"', 'SELECT')
            """, connection);
        Assert.Equal(true, await permissions.ExecuteScalarAsync());
        await using var schema = new NpgsqlCommand("""
            CREATE TABLE public.dev_schema_probe (id integer);
            ALTER TABLE public.dev_schema_probe ADD COLUMN note text;
            DROP TABLE public.dev_schema_probe;
            """, connection);
        await schema.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task Run_AlreadyCurrent_SucceedsWithoutReapplyingMigrations()
    {
        // Arrange
        await using var database = await MigrationDatabase.StartAsync();
        Assert.Equal((0, string.Empty), await database.RunAsync());
        await using var context = database.Context();
        var applied = (await context.Database.GetAppliedMigrationsAsync()).ToArray();
        Assert.NotEmpty(applied);

        // Act
        var result = await database.RunAsync();

        // Assert
        Assert.Equal((0, string.Empty), result);
        Assert.Equal(applied, await context.Database.GetAppliedMigrationsAsync());
    }

    [Fact]
    public async Task Bootstrap_ExistingRestrictedDatabase_TransfersOwnershipWithoutLosingData()
    {
        // Arrange
        await using var database = await MigrationDatabase.StartAsync(bootstrap: false);
        await using var context = database.Context(admin: true);
        await context.Database.MigrateAsync();
        await database.ExecuteAdminAsync("""
            CREATE ROLE api_development LOGIN PASSWORD 'isolated-test-password';
            GRANT CONNECT ON DATABASE pam_migrations TO api_development;
            GRANT USAGE ON SCHEMA public TO api_development;
            CREATE TABLE public.preserved_data (id integer PRIMARY KEY, note text);
            INSERT INTO public.preserved_data VALUES (1, 'keep this row');
            """);

        // Act
        await database.BootstrapAsync();
        await database.BootstrapAsync();
        var result = await database.RunAsync();

        // Assert
        Assert.Equal((0, string.Empty), result);
        await using var connection = new NpgsqlConnection(database.AppConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand("SELECT note FROM public.preserved_data WHERE id = 1", connection);
        Assert.Equal("keep this row", await command.ExecuteScalarAsync());
        await using var ownership = new NpgsqlCommand("""
            SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = 'audit_events'
            """, connection);
        Assert.Equal(MigrationDatabase.AppUser, await ownership.ExecuteScalarAsync());
    }
}
