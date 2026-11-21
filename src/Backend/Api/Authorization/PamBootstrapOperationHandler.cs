using Api.Authentication;
using Application.Authorization;
using Microsoft.AspNetCore.Authorization;

namespace Api.Authorization;

public sealed class PamBootstrapOperationHandler : AuthorizationHandler<PamBootstrapOperationRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PamBootstrapOperationRequirement requirement)
    {
        if (context.User.HasClaim(PamClaimTypes.Bootstrap, "true") && !BootstrapPermissions.Allows(requirement.Permission))
        {
            context.Fail();
        }
        else
        {
            context.Succeed(requirement);
        }
        return Task.CompletedTask;
    }
}
