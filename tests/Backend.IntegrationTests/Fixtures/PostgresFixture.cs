using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Backend.IntegrationTests.Fixtures;

public sealed class PostgresFixture : IAsyncLifetime
{
    private const string TemplateDatabaseName = "pam_test_template";
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:18.0-alpine").Build();

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        await using var admin = new NpgsqlConnection(_container.GetConnectionString());
        await admin.OpenAsync();
        await using (var create = new NpgsqlCommand($"CREATE DATABASE {TemplateDatabaseName}", admin))
        {
            await create.ExecuteNonQueryAsync();
        }
        // Apply the real migrations once, then close every template connection.
        // No test receives this database, so schema/data mutations stay in clones.
        await using (var template = CreateContext(TemplateDatabaseName))
        {
            await template.Database.MigrateAsync();
        }
        await using var protect = new NpgsqlCommand($"ALTER DATABASE {TemplateDatabaseName} ALLOW_CONNECTIONS false", admin);
        await protect.ExecuteNonQueryAsync();
    }
    public Task DisposeAsync() => _container.DisposeAsync().AsTask();

    public async Task<TestDatabase> CreateDatabaseAsync(params IInterceptor[] interceptors)
    {
        var name = "test_" + Guid.NewGuid().ToString("N");
        await using var admin = new NpgsqlConnection(_container.GetConnectionString());
        await admin.OpenAsync();
        await using var command = new NpgsqlCommand($"CREATE DATABASE \"{name}\" TEMPLATE {TemplateDatabaseName}", admin);
        await command.ExecuteNonQueryAsync();
        return new TestDatabase(CreateContext(name, interceptors), _container.GetConnectionString(), name);
    }

    private PamDbContext CreateContext(string name, params IInterceptor[] interceptors)
    {
        var connection = new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
        {
            Database = name,
            Pooling = false
        };
        var options = new DbContextOptionsBuilder<PamDbContext>()
            .UseNpgsql(connection.ConnectionString)
            .UseSnakeCaseNamingConvention()
            .AddInterceptors(interceptors)
            .Options;
        return new PamDbContext(options);
    }
}

public sealed class TestDatabase(PamDbContext context, string adminConnection, string name) : IAsyncDisposable
{
    public PamDbContext Context { get; } = context;

    public async ValueTask DisposeAsync()
    {
        await Context.DisposeAsync();
        await using var admin = new NpgsqlConnection(adminConnection);
        await admin.OpenAsync();
        await using var command = new NpgsqlCommand($"DROP DATABASE \"{name}\" WITH (FORCE)", admin);
        await command.ExecuteNonQueryAsync();
    }
}
