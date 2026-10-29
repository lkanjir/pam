using System.Globalization;
using System.Net.Http.Json;
using Api.Authentication;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Sessions;
using Backend.Tests.Support;
using Infrastructure.Persistence.Entities;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using StackExchange.Redis;

namespace Backend.IntegrationTests.Resources;

internal sealed class ResourceTestContext : IAsyncDisposable
{
    public const string CorrelationId = "resource-http-request";

    private readonly WebApplication _application;

    private ResourceTestContext(
        TestDatabase database,
        TestTimeProvider clock,
        long actorId,
        ManagedResource resource,
        WebApplication application)
    {
        Database = database;
        Clock = clock;
        ActorId = actorId;
        Resource = resource;
        _application = application;
        Client = application.GetTestClient();
    }

    public TestDatabase Database { get; }
    public TestTimeProvider Clock { get; }
    public long ActorId { get; }
    public ManagedResource Resource { get; }
    public HttpClient Client { get; }
    public string ResourceUrl => $"/api/resources/{Resource.PublicId}";

    public static async Task<ResourceTestContext> CreateAsync(PostgresFixture postgres, IConnectionMultiplexer redis)
    {
        var database = await postgres.CreateDatabaseAsync();
        var clock = new TestTimeProvider();
        string principalId = await SessionTestHost.SeedPrincipalAsync(database);
        var creator = new Principal { Issuer = "test-issuer", Subject = "ivan" };
        var resource = new ManagedResource
        {
            Name = "Original target",
            Description = "Original description",
            ResourceType = "linux",
            Environment = "dev",
            CreatedAt = clock.Now.AddHours(-1).UtcDateTime,
            ModifiedAt = clock.Now.AddHours(-1).UtcDateTime,
            CreatedByPrincipal = creator,
            ModifiedByPrincipal = creator
        };
        database.Context.ManagedResources.Add(resource);
        await database.Context.SaveChangesAsync();
        var application = await SessionTestHost.CreateSessionServerAsync(
            database, clock, principalId, redis, app => app.Use(async (context, next) =>
            {
                context.TraceIdentifier = CorrelationId;
                await next(context);
            }));

        return new ResourceTestContext(
            database, clock, long.Parse(principalId, CultureInfo.InvariantCulture), resource, application);
    }

    public async Task AuthenticateAsync()
    {
        using var login = await Client.GetAsync("/login");
        login.EnsureSuccessStatusCode();
        SessionTestHost.UpdateCookie(Client, login);
        using var antiforgery = await Client.GetAsync("/api/auth/antiforgery");
        antiforgery.EnsureSuccessStatusCode();
        SessionTestHost.UpdateCookie(Client, antiforgery);
        var tokens = await antiforgery.Content.ReadFromJsonAsync<AntiforgeryTokenResponse>();
        Client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", tokens!.RequestToken);
    }

    public Task<ManagedResource> ReadResourceAsync()
    {
        Database.Context.ChangeTracker.Clear();
        return Database.Context.ManagedResources.IgnoreQueryFilters().AsNoTracking()
            .SingleAsync(resource => resource.Id == Resource.Id);
    }

    public Task<int> CountAuditEventsAsync(string eventType) =>
        Database.Context.AuditEvents.CountAsync(e => e.ResourceId == Resource.Id && e.EventType == eventType);

    public async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await _application.DisposeAsync();
        await Database.DisposeAsync();
    }
}
