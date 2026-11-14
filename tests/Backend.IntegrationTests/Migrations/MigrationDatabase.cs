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
        var builder = new PostgreSqlBuilder("postgres:18.0-alpine")
            .WithDatabase("pam_migrations")
            .WithUsername("migration_admin")
            .WithPassword("isolated-admin-password")
            .WithEnvironment("APP_DB_USER", AppUser)
            .WithEnvironment("APP_DB_PASSWORD", AppPassword);
        if (bootstrap)
        {
            builder = builder.WithResourceMapping(
                new FileInfo(Path.Combine(AppContext.BaseDirectory, "MigrationScripts/dev-bootstrap.sh")),
                new FileInfo("/docker-entrypoint-initdb.d/01-create-app-user.sh"));
        }

        var container = builder.Build();
        try
        {
            await container.StartAsync();
            return new MigrationDatabase(container);
        }
        catch
        {
            await container.DisposeAsync();
            throw;
        }
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
