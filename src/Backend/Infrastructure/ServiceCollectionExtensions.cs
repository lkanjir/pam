using Application.Identity;
using Infrastructure.Authentication;
using Application.Sessions;
using Infrastructure.Identity;
using Infrastructure.Persistence;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.StackExchangeRedis;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

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
            options.UseNpgsql(databaseOptions.ConnectionString).UseSnakeCaseNamingConvention();
        });

        services.AddHealthChecks().AddDbContextCheck<PamDbContext>(name: "database", tags: ["ready"]);
        services.PostConfigure<HealthCheckServiceOptions>(options =>
        {
            var databaseCheck = options.Registrations.Single(registration => registration.Name == "database");

            databaseCheck.Timeout = TimeSpan.FromSeconds(1);
        });

        services.AddOptions<RedisOptions>().Bind(configuration.GetSection(RedisOptions.SectionName))
            .Validate(options => !string.IsNullOrWhiteSpace(options.Host), "Redis:Host is required")
            .Validate(options => options.Port is > 0 and <= 65535, "Redis:Port must be in interval [1-65535]")
            .Validate(options => !string.IsNullOrWhiteSpace(options.User), "Redis:User name is required")
            .Validate(options => !string.IsNullOrWhiteSpace(options.Password), "Redis:Password is required")
            .ValidateOnStart();

        services.AddHealthChecks()
            .AddRedis(
                connectionMultiplexerFactory: serviceProvider =>
                    serviceProvider.GetRequiredService<IConnectionMultiplexer>(), name: "redis", tags: ["ready"],
                timeout: TimeSpan.FromSeconds(1));


        services.AddSingleton<IConnectionMultiplexer>(serviceProvider =>
        {
            var redisOptions = serviceProvider.GetRequiredService<IOptions<RedisOptions>>().Value;
            var redisConfiguration = new ConfigurationOptions
            {
                User = redisOptions.User,
                Password = redisOptions.Password,
                AbortOnConnectFail = false,
            };
            redisConfiguration.EndPoints.Add(redisOptions.Host, redisOptions.Port);

            return ConnectionMultiplexer.Connect(redisConfiguration);
        });

        services.AddSingleton<ISessionTicketStore, RedisTicketStore>();

        services.AddDataProtection().SetApplicationName("pam");
        services.AddOptions<KeyManagementOptions>().Configure<IConnectionMultiplexer>((options, redis) =>
        {
            options.XmlRepository = new RedisXmlRepository(() => redis.GetDatabase(), "pam:data-protection:keys");
        });

        services.AddScoped<IPrincipalIdentityReader, PrincipalIdentityReader>();
        services.AddScoped<ISessionLedgerWriter, SessionLedgerWriter>();
        services.AddScoped<SessionTerminator>();

        return services;
    }
}
