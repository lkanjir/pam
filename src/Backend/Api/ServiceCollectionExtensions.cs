using Api.Configuration;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddKeycloak(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<KeycloakOptions>().Bind(configuration.GetSection(KeycloakOptions.SectionName))
            .Validate(options => Uri.TryCreate(options.Authority, UriKind.Absolute, out var uri) &&
                                 (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps),
                "Keycloak:Authority must be an absolute HTTP or HTTPS URL")
            .Validate(options => Uri.TryCreate(options.MetadataAddress, UriKind.Absolute, out var uri) &&
                                 (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps),
                "Keycloak:MetadataAddress must be an absolute HTTP or HTTPS URL")
            .Validate(options => !string.IsNullOrWhiteSpace(options.ClientId),
                "Keycloak:ClientId is required")
            .Validate(options => !string.IsNullOrWhiteSpace(options.ClientSecret),
                "Keycloak:ClientSecret is required")
            .ValidateOnStart();

        return services;
    }

    public static IServiceCollection AddPamAuthentication(this IServiceCollection services,
        IHostEnvironment environment)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;

            options.DefaultChallengeScheme = "oidc";
        }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.Cookie.Name = "pam.session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.Path = "/";
            options.Cookie.SecurePolicy = environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
            options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            options.SlidingExpiration = true;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });

        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<ITicketStore>((
                options, ticketStore) =>
            {
                options.SessionStore = ticketStore;
            });

        services.AddAuthorization();
        
        
        return services;
    }
}