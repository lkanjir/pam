using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace Api.Authentication;

internal static class PamSessionSignIn
{
    public const string Scheme = "PamSessionSignIn";

    public static AuthenticationBuilder AddPamSessionSignIn(this AuthenticationBuilder builder)
    {
        builder.AddCookie(Scheme);
        builder.Services.AddOptions<CookieAuthenticationOptions>(Scheme)
            .Configure<IServiceProvider>((options, services) =>
            {
                // Resolve lazily: injecting this monitor into its own options
                // factory would introduce a circular DI dependency.
                var session = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
                    .Get(CookieAuthenticationDefaults.AuthenticationScheme);
                // Read and write the same cookie through two standard handlers.
                // Only explicit sign-in is forwarded; reading, renewal and logout
                // continue to use the primary scheme and its request cookie.
                options.Cookie = session.Cookie;
                options.CookieManager = new SignInCookieManager(session.CookieManager);
                options.TicketDataFormat = session.TicketDataFormat;
                options.SessionStore = session.SessionStore;
                options.TimeProvider = session.TimeProvider;
                options.ExpireTimeSpan = session.ExpireTimeSpan;
                options.ClaimsIssuer = session.ClaimsIssuer;
                options.LoginPath = session.LoginPath;
                options.ReturnUrlParameter = session.ReturnUrlParameter;
                options.EventsType = typeof(PamSignInCookieEvents);
            });
        return builder;
    }
}
