using Api.Authentication;
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

    public static IServiceCollection AddPamSessionOptions(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<PamSessionOptions>()
            .Bind(configuration.GetSection(PamSessionOptions.SectionName))
            .Validate(
                options => options.IdleTimeout > TimeSpan.Zero,
                "PamSession:IdleTimeout must be positive.")
            .Validate(
                options => options.AbsoluteTimeout >= options.IdleTimeout,
                "PamSession:AbsoluteTimeout must be at least IdleTimeout.")
            .ValidateOnStart();

        return services;
    }

    public static IServiceCollection AddPamAuthentication(this IServiceCollection services,
        IHostEnvironment environment)
    {
        services.AddSingleton<PamSessionLifetime>();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;

            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.ForwardSignIn = PamSessionSignIn.Scheme;
            options.Cookie.Name = "pam.session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.Path = "/";
            options.Cookie.SecurePolicy = environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
            options.SlidingExpiration = true;
            options.Events.OnValidatePrincipal = PamPrincipalValidation.ValidateAsync;
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
        }).AddPamSessionSignIn().AddOpenIdConnect("oidc", _ => { });

        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<ITicketStore>((
                options, ticketStore) =>
            {
                options.SessionStore = ticketStore;
            })
            .Configure<IOptions<PamSessionOptions>>((options, sessionOptions) =>
            {
                options.ExpireTimeSpan = sessionOptions.Value.IdleTimeout;
            })
            .Configure<PamSessionLifetime>((options, sessionLifetime) =>
            {
                // Every explicit sign-in starts a new server-side session.
                options.Events.OnSigningIn = context =>
                {
                    sessionLifetime.Initialize(context.Properties);
                    return Task.CompletedTask;
                };
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
            options.EventsType = typeof(PamOpenIdConnectEvents);

            options.RequireHttpsMetadata = !environment.IsDevelopment();

            if (environment.IsDevelopment())
            {
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
                options.NonceCookie.SameSite = SameSiteMode.Lax;
                options.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
            }
        });

        services.AddScoped<PamOpenIdConnectEvents>();

        return services;
    }

    public static IServiceCollection AddPamAntiforgery(this IServiceCollection services, IHostEnvironment environment)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.Cookie.Name = "pam.antiforgery";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.Path = "/";
            options.Cookie.SecurePolicy = environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
        });
        
        return services;
    }
}
