using System.Net;
using Api;
using Api.Authentication;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Persistence.Entities;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using StackExchange.Redis;

namespace Backend.IntegrationTests.Sessions;

[CollectionDefinition("Cookie sessions")]
public sealed class CookieSessionCollection : ICollectionFixture<PostgresFixture>, ICollectionFixture<RedisFixture>;

internal static class SessionTestHost
{
    public static async Task<WebApplication> CreateSessionServerAsync(
        TestDatabase database, TestTimeProvider clock, string principalId, IConnectionMultiplexer redis)
    {
        var builder = CreateBuilder(database, clock, redis);
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.UsePamApi();
        // Replace only the external identity provider's sign-in entry point.
        app.MapGet("/login", async (HttpContext context) =>
        {
            var ticket = SessionTestData.Ticket(clock.Now, principalId);
            var properties = new AuthenticationProperties
            {
                IsPersistent = context.Request.Query["persistent"] == "True",
                RedirectUri = context.Request.Query["redirect"] == "true" ? "/api/me" : null
            };
            await context.SignInAsync("Cookies", ticket.Principal, properties);
        }).AllowAnonymous();
        await app.StartAsync();
        return app;
    }

    public static ServiceProvider CreateServices(TestDatabase database, TimeProvider clock,
        IConnectionMultiplexer redis) => CreateBuilder(database, clock, redis).Services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });

    private static WebApplicationBuilder CreateBuilder(TestDatabase database, TimeProvider clock,
        IConnectionMultiplexer redis)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            EnvironmentName = "Development",
            ApplicationName = typeof(PamApplication).Assembly.GetName().Name
        });
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Database:ConnectionString"] = database.Context.Database.GetConnectionString(),
            ["Redis:Host"] = "localhost",
            ["Redis:Port"] = "6379",
            ["Redis:User"] = "test",
            ["Redis:Password"] = "test",
            ["Keycloak:Authority"] = "https://identity.example/realms/pam",
            ["Keycloak:MetadataAddress"] = "https://identity.example/realms/pam/.well-known/openid-configuration",
            ["Keycloak:ClientId"] = "test-bff",
            ["Keycloak:ClientSecret"] = "test-secret",
            ["PamSession:IdleTimeout"] = "00:30:00",
            ["PamSession:AbsoluteTimeout"] = "08:00:00"
        });
        builder.Services.AddPamApi(builder.Configuration, builder.Environment);
        builder.Services.Replace(ServiceDescriptor.Singleton(clock));
        builder.Services.Replace(ServiceDescriptor.Singleton(redis));
        builder.Services.Replace(ServiceDescriptor.Singleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider()));
        builder.Services.Configure<CookieAuthenticationOptions>("Cookies", options => options.TimeProvider = clock);
        return builder;
    }

    public static void UpdateCookie(HttpClient client, HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var cookies)) return;
        // Standard sign-out followed by sign-in emits deletion and replacement.
        // Apply them in response order, as a browser does.
        var jar = new CookieContainer();
        if (client.DefaultRequestHeaders.TryGetValues("Cookie", out var existing))
            foreach (var cookie in existing.SelectMany(header => header.Split(';')))
                jar.SetCookies(client.BaseAddress!, cookie.Trim());
        foreach (var cookie in cookies)
            jar.SetCookies(client.BaseAddress!, cookie);
        client.DefaultRequestHeaders.Remove("Cookie");
        var header = jar.GetCookieHeader(client.BaseAddress!);
        if (header.Length > 0) client.DefaultRequestHeaders.Add("Cookie", header);
    }

    public static Task RejectLogoutAuditAsync(TestDatabase database) =>
        database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_session_end CHECK (event_type <> 'authentication.session.ended')");

    public static async Task<string> LoginAsync(ServiceProvider services, TimeProvider clock, string principalId)
    {
        await using var scope = services.CreateAsyncScope();
        var context = CreateContext(scope.ServiceProvider);
        var ticket = SessionTestData.Ticket(clock.GetUtcNow(), principalId);
        await context.SignInAsync("Cookies", ticket.Principal, ticket.Properties);
        return context.Response.Headers.SetCookie.Single(value => value!.StartsWith("pam.session="))!.Split(';')[0];
    }

    public static DefaultHttpContext CreateLogoutContext(IServiceProvider services, string cookie)
    {
        var context = CreateContext(services);
        context.Request.Method = "POST";
        context.Request.Path = "/auth/logout";
        context.Request.Headers.Cookie = cookie;
        return context;
    }

    public static Task ExecuteLogoutEndpointAsync(HttpContext context)
    {
        // Execute the real endpoint delegate, including its internal termination feature.
        // Authorization/antiforgery middleware are outside this lifecycle test's scope.
        var routes = new TestRouteBuilder(context.RequestServices);
        routes.MapAuthenticationEndpoints();
        var endpoint = routes.DataSources.SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>().Single(e => e.RoutePattern.RawText == "/auth/logout");
        return endpoint.RequestDelegate!(context);
    }

    private sealed class TestRouteBuilder(IServiceProvider services) : IEndpointRouteBuilder
    {
        public IServiceProvider ServiceProvider => services;
        public ICollection<EndpointDataSource> DataSources { get; } = new List<EndpointDataSource>();
        public IApplicationBuilder CreateApplicationBuilder() => new ApplicationBuilder(services);
    }

    public static DefaultHttpContext CreateContext(IServiceProvider services)
    {
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = "http";
        return context;
    }

    public static async Task<string> SeedPrincipalAsync(TestDatabase database)
    {
        var principal = new Principal { Issuer = "https://identity.example/realms/pam", Subject = "ana" };
        database.Context.Principals.Add(principal);
        await database.Context.SaveChangesAsync();
        await database.Context.Database.ExecuteSqlInterpolatedAsync($"UPDATE principals SET is_enabled = true WHERE id = {principal.Id}");
        return principal.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }
}
