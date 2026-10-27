using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Options;

namespace Api.Authentication;

// Keep the standard cookie authentication, renewal and logout behavior, but allocate
// a new ticket-store key for explicit sign-ins instead of renewing the old identity.
public sealed class PamCookieAuthenticationHandler(
    IOptionsMonitor<CookieAuthenticationOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder) : CookieAuthenticationHandler(options, logger, encoder)
{
    private const string SessionIdClaim = "Microsoft.AspNetCore.Authentication.Cookies-SessionId";
    private bool _signingIn;

    protected override Task FinishResponseAsync() =>
        _signingIn ? Task.CompletedTask : base.FinishResponseAsync();

    protected override async Task HandleSignInAsync(ClaimsPrincipal user, AuthenticationProperties? properties)
    {
        _signingIn = true;
        var store = Options.SessionStore
            ?? throw new InvalidOperationException("PAM requires a server-side session store.");
        properties ??= new AuthenticationProperties();
        properties.IssuedUtc ??= TimeProvider.GetUtcNow();
        properties.ExpiresUtc ??= properties.IssuedUtc.Value.Add(Options.ExpireTimeSpan);

        var cookieOptions = Options.Cookie.Build(Context);
        cookieOptions.Expires = null;
        var signingIn = new CookieSigningInContext(Context, Scheme, Options, user, properties, cookieOptions);
        await Events.SigningIn(signingIn);

        // Retire the old session before issuing a new identity. A persistence failure
        // must never leave the old cookie pointing at the new principal.
        var binding = Context.Features.Get<ITlsTokenBindingFeature>()?.GetProvidedTokenBindingId();
        var bindingText = binding is null ? null : Convert.ToBase64String(binding);
        var oldCookie = Options.CookieManager.GetRequestCookie(Context, Options.Cookie.Name!);
        var oldKey = oldCookie is null ? null
            : Options.TicketDataFormat.Unprotect(oldCookie, bindingText)?.Principal.FindFirst(SessionIdClaim)?.Value;
        if (oldKey is not null)
        {
            var previousTermination = Context.Features.Get<SessionTermination>();
            Context.Features.Set(new SessionTermination("reauthentication"));
            try
            {
                await store.RemoveAsync(oldKey, Context, Context.RequestAborted);
            }
            finally
            {
                Context.Features.Set(previousTermination);
            }
        }

        var ticket = new AuthenticationTicket(signingIn.Principal!, signingIn.Properties, Scheme.Name);
        var key = await store.StoreAsync(ticket, Context, Context.RequestAborted);
        var cookiePrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(SessionIdClaim, key, ClaimValueTypes.String, Options.ClaimsIssuer)], Scheme.Name));
        var cookieTicket = new AuthenticationTicket(cookiePrincipal, null, Scheme.Name);
        var cookieValue = Options.TicketDataFormat.Protect(cookieTicket, bindingText);
        if (signingIn.Properties.IsPersistent)
            signingIn.CookieOptions.Expires = signingIn.Properties.ExpiresUtc;
        Options.CookieManager.AppendResponseCookie(Context, Options.Cookie.Name!, cookieValue, signingIn.CookieOptions);
        await Events.SignedIn(new CookieSignedInContext(
            Context, Scheme, signingIn.Principal!, signingIn.Properties, Options));

        Response.Headers.CacheControl = "no-cache,no-store";
        Response.Headers.Pragma = "no-cache";
        Response.Headers.Expires = "Thu, 01 Jan 1970 00:00:00 GMT";
        if (Response.StatusCode == StatusCodes.Status200OK && signingIn.Properties.RedirectUri is { } redirectUri)
            await Events.RedirectToReturnUrl(new RedirectContext<CookieAuthenticationOptions>(
                Context, Scheme, Options, signingIn.Properties, redirectUri));
    }
}
