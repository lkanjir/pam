using Api.Authentication;
using Api.Errors;
using Api.Filters;
using Infrastructure;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace Api;

public static class PamApplication
{
    public static IServiceCollection AddPamApi(this IServiceCollection services,
        IConfiguration configuration, IHostEnvironment environment)
    {
        services.AddSingleton<TimeProvider>(TimeProvider.System);
        services.AddInfrastructure(configuration);
        services.AddPamAuthentication(configuration, environment);
        services.AddPamAntiforgery(environment);
        services.AddOpenApi();
        services.AddPamErrorHandling();
        return services;
    }

    public static WebApplication UsePamApi(this WebApplication app)
    {
        app.UsePamErrorHandling();
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") });
        app.MapGroup("/api").RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>()
            .MapAuthenticationEndpoints();

        if (app.Environment.IsDevelopment())
            app.MapOpenApi();
        return app;
    }
}
