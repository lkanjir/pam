using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;

namespace Api.Authorization;

public sealed class PamAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    private readonly AuthorizationMiddlewareResultHandler _defaultHandler = new();

    public Task HandleAsync(RequestDelegate next, HttpContext context, AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Forbidden && authorizeResult.AuthorizationFailure is { } failure
            && failure.FailedRequirements.Any()
            && failure.FailedRequirements.All(requirement => requirement is PamRecentAuthenticationRequirement))
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden,
                title: "Recent authentication is required.",
                extensions: new Dictionary<string, object?> { ["code"] = "recent_auth_required" }).ExecuteAsync(context);
        }

        return _defaultHandler.HandleAsync(next, context, policy, authorizeResult);
    }
}
