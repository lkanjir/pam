using Infrastructure.Persistence;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Infrastructure;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<DatabaseOptions>().Bind(configuration.GetSection(DatabaseOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.ConnectionString),
                "Database:ConnectionString is required").ValidateOnStart();

        services.AddDbContextPool<PamDbContext>((serviceProvider, options) =>
        {
            var databaseOptions = serviceProvider.GetRequiredService<IOptions<DatabaseOptions>>().Value;
            options.UseNpgsql(databaseOptions.ConnectionString);
        });

        services.AddHealthChecks().AddDbContextCheck<PamDbContext>(name: "database", tags: ["ready"]);
        services.PostConfigure<HealthCheckServiceOptions>(options =>
        {
            var databaseCheck = options.Registrations.Single(registration => registration.Name == "database");

            databaseCheck.Timeout = TimeSpan.FromSeconds(1);
        });
        
        services.AddOptions<RedisOptions>().Bind(configuration.GetSection(RedisOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.ConnectionString),
                "Redis:Connection string is required").ValidateOnStart();

        services.AddHealthChecks()
            .AddRedis(
                connectionStringFactory: serviceProvider =>
                    serviceProvider.GetRequiredService<IOptions<RedisOptions>>().Value.ConnectionString,
                name: "redis", tags: ["ready"], timeout: TimeSpan.FromSeconds(1));

        return services;
    }
}