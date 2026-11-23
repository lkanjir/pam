using Application.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Api.Authorization;

/// <summary>Validates the framework's mapped metadata before the server accepts requests.</summary>
public sealed class PamEndpointAuthorizationStartupFilter(IOptions<AuthorizationOptions> options) : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        next(app);
        var source = app.ApplicationServices.GetRequiredService<EndpointDataSource>();
        foreach (var endpoint in source.Endpoints.OfType<RouteEndpoint>())
        {
            var authorization = endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>();
            var names = authorization.Select(data => data.Policy).OfType<string>().Where(name => name.Length > 0)
                .Concat(endpoint.Metadata.GetMetadata<PamConditionalPermissionMetadata>()?.Permissions ?? [])
                .ToArray();
            if (endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            {
                if (names.Length > 0)
                {
                    throw new InvalidOperationException($"Public endpoint '{endpoint.RoutePattern.RawText}' declares a business policy.");
                }
                continue;
            }

            if (authorization.Count == 0)
            {
                throw new InvalidOperationException($"Endpoint '{endpoint.RoutePattern.RawText}' has no authentication classification.");
            }

            bool hasOperation = false;
            bool needsRecentAuthentication = false;
            foreach (string name in names)
            {
                var policy = options.Value.GetPolicy(name);
                if (policy is null)
                {
                    throw new InvalidOperationException($"Endpoint '{endpoint.RoutePattern.RawText}' references unknown policy '{name}'.");
                }
                if (name is PamPolicies.RecentAuthentication or PamPolicies.PermanentAdministrator)
                {
                    continue;
                }

                _ = PamPermissionRoles.For(name);
                if (!policy.Requirements.OfType<PamBootstrapOperationRequirement>().Any(requirement => requirement.Permission == name))
                {
                    throw new InvalidOperationException($"Endpoint '{endpoint.RoutePattern.RawText}' has no bootstrap boundary for '{name}'.");
                }
                hasOperation = true;
                needsRecentAuthentication |= PamPermissionRoles.RequiresRecentAuthentication(name);
            }

            if (!hasOperation && endpoint.Metadata.GetMetadata<PamSessionEndpointMetadata>() is null)
            {
                throw new InvalidOperationException($"Endpoint '{endpoint.RoutePattern.RawText}' has no operation policy or session classification.");
            }
            if (needsRecentAuthentication && !names.Contains(PamPolicies.RecentAuthentication, StringComparer.Ordinal))
            {
                throw new InvalidOperationException($"Endpoint '{endpoint.RoutePattern.RawText}' is missing its recent-auth policy.");
            }
        }
    };
}
