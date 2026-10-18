using Api.Configuration;

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
}