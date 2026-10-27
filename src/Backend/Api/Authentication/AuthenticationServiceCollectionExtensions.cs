using Api.Configuration;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace Api.Authentication;

public static class AuthenticationServiceCollectionExtensions
{
    public static IServiceCollection AddPamAuthentication(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        AddPamSessionOptions(services, configuration);
        services.AddSingleton<ITicketStore, PamTicketStore>();
        services.AddSingleton<PamSessionLifetime>();
        services.AddScoped<PamCookieEvents>();
        services.AddScoped<PamSignInCookieEvents>();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultSignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultForbidScheme = CookieAuthenticationDefaults.AuthenticationScheme;

            options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        }).AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.ForwardSignIn = PamSessionSignIn.Scheme;
            options.Cookie.Name = "pam.session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.Path = "/";
            options.Cookie.SecurePolicy = environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
            options.SlidingExpiration = true;
            options.EventsType = typeof(PamCookieEvents);
        }).AddPamSessionSignIn().AddPamOpenIdConnect(configuration, environment);

        services.AddOptions<CookieAuthenticationOptions>(CookieAuthenticationDefaults.AuthenticationScheme)
            .Configure<ITicketStore>((options, ticketStore) => options.SessionStore = ticketStore)
            .Configure<IOptions<PamSessionOptions>>((options, sessionOptions) =>
            {
                options.ExpireTimeSpan = sessionOptions.Value.IdleTimeout;
            });

        services.AddAuthorization();

        return services;
    }

    private static IServiceCollection AddPamSessionOptions(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddOptions<PamSessionOptions>()
            .Bind(configuration.GetSection(PamSessionOptions.SectionName))
            .Validate(
                options => options.IdleTimeout > TimeSpan.Zero,
                "PamSession:IdleTimeout must be positive.")
            .Validate(
                options => options.AbsoluteTimeout >= options.IdleTimeout,
                "PamSession:AbsoluteTimeout must be at least IdleTimeout.")
            .ValidateOnStart();

        return services;
    }
}
