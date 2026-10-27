using Application.Identity;
using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

public sealed class PamCookieEvents(IPrincipalIdentityReader principalReader) : CookieAuthenticationEvents
{
    public override async Task ValidatePrincipal(CookieValidatePrincipalContext context)
    {
        if (PamClaims.TryRead(context.Principal!, out var identity))
        {
            var current = await principalReader.FindAsync(identity.Issuer, identity.Subject,
                context.HttpContext.RequestAborted);
            if (current is { IsEnabled: true } && current.Id == identity.Id
                && current.Roles.ToHashSet(StringComparer.Ordinal).SetEquals(identity.Roles))
                return;
        }

        // Revoke before returning: a pending sliding renewal must not restore access.
        context.RejectPrincipal();
        await context.HttpContext.EndPamSessionAsync(SessionEndReason.AccessChanged, context.Scheme.Name);
    }

    public override Task RedirectToLogin(RedirectContext<CookieAuthenticationOptions> context)
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    }

    public override Task RedirectToAccessDenied(RedirectContext<CookieAuthenticationOptions> context)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }
}
