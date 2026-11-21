using Api.AccessRequests;
using Api.Authentication;
using Api.Authorization;
using Api.Errors;
using Api.Filters;
using Api.Principals;
using Api.Resources;
using Infrastructure;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace Api;

public static class PamApplication
{
    public static IServiceCollection AddPamApi(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        services.AddSingleton<TimeProvider>(TimeProvider.System);
        services.AddInfrastructure(configuration);
        services.AddValidation();
        services.AddPamAuthentication(configuration, environment);
        services.AddPamAuthorization();
        services.AddPamAntiforgery(environment);
        services.AddOpenApi();
        services.AddPamErrorHandling();
        return services;
    }

    public static WebApplication UsePamApi(this WebApplication app)
    {
        app.UsePamErrorHandling();
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.StartsWithSegments("/api"))
            {
                context.Response.OnStarting(() =>
                {
                    context.Response.Headers.CacheControl = "no-store";
                    return Task.CompletedTask;
                });
            }

            await next(context);
        });
        app.UseAuthentication();
        app.UseAuthorization();

        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false }).AllowAnonymous();
        app.MapHealthChecks(
            "/health/ready",
            new HealthCheckOptions { Predicate = check => check.Tags.Contains("ready") }).AllowAnonymous();

        var api = app.MapGroup("/api").RequireAuthorization().AddEndpointFilter<AntiforgeryFilter>();
        api.MapAuthenticationEndpoints();
        api.MapResourceEndpoints();
        api.MapAccessRequestEndpoints();
        api.MapPrincipalEndpoints();
        api.MapPrincipalRoleEndpoints();
        api.MapResourceAccessEndpoints();
        api.MapEligibilityEndpoints();

        if (app.Environment.IsDevelopment())
        {
            app.MapOpenApi().AllowAnonymous();
            app.UseSwaggerUI(options =>
            {
                options.SwaggerEndpoint("/openapi/v1.json", "PAM API");
            });
        }

        return app;
    }
}
