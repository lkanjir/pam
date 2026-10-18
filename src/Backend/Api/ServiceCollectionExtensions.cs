using Api.Configuration;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

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

            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
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
        }).AddOpenIdConnect("oidc", _ => { });

        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<ITicketStore>((
                options, ticketStore) =>
            {
                options.SessionStore = ticketStore;
            });

        services.AddAuthorization();

        services.AddOptions<OpenIdConnectOptions>("oidc").Configure<IOptions<KeycloakOptions>>((options,
            keycloakOptions) =>
        {
            var keycloak = keycloakOptions.Value;

            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Authority = keycloak.Authority;
            options.MetadataAddress = keycloak.MetadataAddress;
            options.ClientId = keycloak.ClientId;
            options.ClientSecret = keycloak.ClientSecret;

            options.ResponseType = OpenIdConnectResponseType.Code;
            options.ResponseMode = OpenIdConnectResponseMode.Query;
            options.UsePkce = true;
            
            options.CallbackPath = "/signin-oidc";
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");

            options.SaveTokens = false;
            options.MapInboundClaims = false;

            options.TokenValidationParameters.NameClaimType = "name";
            options.TokenValidationParameters.RoleClaimType = "pam_role";

            options.RequireHttpsMetadata = !environment.IsDevelopment();

            if (environment.IsDevelopment())
            {
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.NonceCookie.SameSite = SameSiteMode.Lax;
                options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            }
        });

        return services;
    }
}