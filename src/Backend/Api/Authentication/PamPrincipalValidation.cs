using System.Globalization;
using System.Security.Claims;
using Application.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

internal static class PamPrincipalValidation
{
    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var user = context.Principal!;
        var issuer = user.FindFirst("pam_issuer")?.Value;
        var subject = user.FindFirst("sub")?.Value;
        var reader = context.HttpContext.RequestServices.GetRequiredService<IPrincipalIdentityReader>();
        var current = issuer is not null && subject is not null
            ? await reader.FindAsync(issuer, subject, context.HttpContext.RequestAborted)
            : null;

        if (current is { IsEnabled: true }
            && current.Id.ToString(CultureInfo.InvariantCulture) == user.FindFirst(ClaimTypes.NameIdentifier)?.Value
            && current.Roles.ToHashSet(StringComparer.Ordinal)
                .SetEquals(user.FindAll("pam_role").Select(claim => claim.Value)))
            return;

        // Revoke before returning: a pending sliding renewal must not restore access.
        context.RejectPrincipal();
        context.HttpContext.Features.Set(new SessionTermination("access_changed"));
        await context.HttpContext.SignOutAsync(context.Scheme.Name);
    }
}
