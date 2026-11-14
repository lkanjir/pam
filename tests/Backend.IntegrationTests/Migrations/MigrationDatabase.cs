using System.Globalization;
using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Migrator;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Backend.IntegrationTests.Migrations;

internal sealed class MigrationDatabase(PostgreSqlContainer container) : IAsyncDisposable
{
    private static readonly string[] BootstrapCommand = ["sh", "/tmp/dev-bootstrap.sh"];
    public const string AppUser = "api_development";
    public const string AppPassword = "isolated-test-password";

    public PostgreSqlContainer Container { get; } = container;
    public string AdminConnection => Container.GetConnectionString();
    public string AppConnection => new NpgsqlConnectionStringBuilder(AdminConnection)
    {
        Username = AppUser,
        Password = AppPassword
    }.ConnectionString;

    public static async Task<MigrationDatabase> StartAsync(bool bootstrap = true)
    {
        var container = new PostgreSqlBuilder("postgres:18.0-alpine")
            .WithDatabase("pam_migrations")
            .WithUsername("migration_admin")
            .WithPassword("isolated-admin-password")
            .WithEnvironment("APP_DB_USER", AppUser)
            .WithEnvironment("APP_DB_PASSWORD", AppPassword)
            .WithResourceMapping(new FileInfo(Path.Combine(AppContext.BaseDirectory, "MigrationScripts/dev-bootstrap.sh")),
                new FileInfo("/tmp/dev-bootstrap.sh"))
            .WithResourceMapping(new FileInfo(Path.Combine(AppContext.BaseDirectory, "MigrationScripts/app-permissions.sql")),
                new FileInfo("/tmp/app-permissions.sql"))
            .Build();
        try
        {
            await container.StartAsync();
            var database = new MigrationDatabase(container);
            if (bootstrap)
            {
                await database.BootstrapAsync();
            }

            return database;
        }
        catch
        {
            await container.DisposeAsync();
            throw;
        }
    }

    public async Task BootstrapAsync()
    {
        var result = await Container.ExecAsync(BootstrapCommand);
        Assert.True(result.ExitCode == 0, result.Stdout + result.Stderr);
        Assert.Contains("COMMIT", result.Stdout, StringComparison.Ordinal);
    }

    public async Task<(int ExitCode, string Error)> RunAsync()
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["Database:ConnectionString"] = AppConnection }).Build();
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        int result = await DevelopmentMigrator.RunAsync(configuration, "Development", output, error);
        return (result, error.ToString());
    }

    public async Task<(long ExitCode, string Error)> ApplyProductionPermissionsAsync()
    {
        string[] command = ["psql", "-X", "-U", "migration_admin", "-d", "pam_migrations",
            "--set=api_role=" + AppUser, "--file=/tmp/app-permissions.sql"];
        var result = await Container.ExecAsync(command);
        return (result.ExitCode ?? -1, result.Stderr);
    }

    public PamDbContext Context(bool admin = false) => new(new DbContextOptionsBuilder<PamDbContext>()
        .UseNpgsql(admin ? AdminConnection : AppConnection).UseSnakeCaseNamingConvention().Options);

    public async Task ExecuteAdminAsync(string sql)
    {
        await using var connection = new NpgsqlConnection(AdminConnection);
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(sql, connection);
        await command.ExecuteNonQueryAsync();
    }

    public ValueTask DisposeAsync() => Container.DisposeAsync();
}
