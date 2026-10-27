using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

internal static class PamSessionSignOut
{
    public static async Task EndPamSessionAsync(this HttpContext context, SessionEndReason reason,
        string scheme = CookieAuthenticationDefaults.AuthenticationScheme)
    {
        // ITicketStore removal runs before the SigningOut event and does not
        // receive AuthenticationProperties. Keep this framework bridge local
        // to sign-out, including nested calls and failures.
        var previous = context.Features.Get<EndRequest>();
        context.Features.Set(new EndRequest(reason));
        try
        {
            await context.SignOutAsync(scheme);
        }
        finally
        {
            context.Features.Set(previous);
        }
    }

    internal static SessionEndReason? GetEndReason(HttpContext context) =>
        context.Features.Get<EndRequest>()?.Reason;

    private sealed record EndRequest(SessionEndReason Reason);
}
