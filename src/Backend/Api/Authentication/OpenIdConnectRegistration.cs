using Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Api.Authentication;

internal static class OpenIdConnectRegistration
{
    public static AuthenticationBuilder AddPamOpenIdConnect(
        this AuthenticationBuilder builder,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var services = builder.Services;
        AddKeycloak(services, configuration);
        builder.AddOpenIdConnect("oidc", _ => { });

        services.AddOptions<OpenIdConnectOptions>("oidc").Configure<IOptions<KeycloakOptions>>((options, keycloakOptions) =>
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

            options.TokenValidationParameters.NameClaimType = PamClaimTypes.DisplayName;
            options.TokenValidationParameters.RoleClaimType = PamClaimTypes.Role;
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

        return builder;
    }

    private static IServiceCollection AddKeycloak(this IServiceCollection services, IConfiguration configuration)
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
}
