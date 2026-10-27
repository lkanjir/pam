using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

public sealed class PamSignInCookieEvents(PamSessionLifetime lifetime) : CookieAuthenticationEvents
{
    public override async Task SigningIn(CookieSigningInContext context)
    {
        lifetime.Initialize(context.Properties);
        var previous = await context.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (previous.Succeeded)
            await context.HttpContext.EndPamSessionAsync(SessionEndReason.Reauthentication);
    }
}
