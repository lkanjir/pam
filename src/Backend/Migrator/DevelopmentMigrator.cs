using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Migrator;

public static class DevelopmentMigrator
{
    public static async Task<int> RunAsync(
        IConfiguration configuration,
        string environmentName,
        TextWriter output,
        TextWriter error,
        CancellationToken cancellationToken = default)
    {
        if (!string.Equals(environmentName, Environments.Development, StringComparison.OrdinalIgnoreCase))
        {
            await error.WriteLineAsync("The development migrator can run only in Development. Production uses reviewed SQL.");
            return 1;
        }

        var connectionString = configuration["Database:ConnectionString"];
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            await error.WriteLineAsync("Database:ConnectionString is required. Configure the API's shared User Secrets.");
            return 1;
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var options = new DbContextOptionsBuilder<PamDbContext>()
                .UseNpgsql(connectionString)
                .UseSnakeCaseNamingConvention()
                .Options;
            await using var database = new PamDbContext(options);
            await output.WriteLineAsync("Applying pending development database migrations...");
            await database.Database.MigrateAsync(cancellationToken);
            await output.WriteLineAsync("Development database migrations are ready.");
            return 0;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            await error.WriteLineAsync("Development migration was cancelled.");
            return 130;
        }
        catch (Exception exception)
        {
            // Never print a connection string, SQL parameters or provider exception messages.
            await error.WriteLineAsync($"Development migration failed ({exception.GetType().Name}).");
            return 1;
        }
    }
}
