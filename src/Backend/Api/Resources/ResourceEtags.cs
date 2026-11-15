using System.Globalization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.OpenApi;

namespace Api.Resources;

public static class ResourceEtags
{
    public static string Format(uint version) => $"\"{version.ToString("x8", CultureInfo.InvariantCulture)}\"";

    public static ProblemHttpResult? RequireVersion(HttpRequest request, string? ifMatch, out uint version)
    {
        version = 0;
        if (!request.Headers.TryGetValue("If-Match", out var header))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status428PreconditionRequired,
                title: "An If-Match resource version is required.");
        }

        string value = ifMatch ?? string.Empty;
        if (header.Count != 1 || value.Length != 10 || value[0] != '"' || value[^1] != '"'
            || !uint.TryParse(value.AsSpan(1, 8), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out version)
            || version == 0 || !string.Equals(value, Format(version), StringComparison.Ordinal))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status400BadRequest,
                title: "If-Match must contain one strong ETag returned by the resource GET endpoint.");
        }

        return null;
    }
    public static RouteHandlerBuilder WithResourceVersion(this RouteHandlerBuilder builder) =>
        builder.AddOpenApiOperationTransformer((operation, _, _) =>
        {
            if (operation.Parameters?.OfType<OpenApiParameter>().FirstOrDefault(item => item.Name == "If-Match") is { } header)
            {
                header.Required = true;
            }

            return Task.CompletedTask;
        });

}
