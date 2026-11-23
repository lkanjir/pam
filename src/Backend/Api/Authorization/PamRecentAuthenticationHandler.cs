using Api.Authentication;
using Application.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Api.Authorization;

public sealed class PamRecentAuthenticationHandler(TimeProvider timeProvider)
    : AuthorizationHandler<PamRecentAuthenticationRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context,
        PamRecentAuthenticationRequirement requirement)
    {
        if (RecentAuthentication.IsSatisfied(PamAuthenticationTime.Read(context.User), timeProvider.GetUtcNow()))
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
