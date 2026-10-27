using Api.Authentication;
using Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Application.Sessions;
using Backend.Tests.Support;
using FakeItEasy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis;

namespace Backend.UnitTests.Authentication;

internal sealed class TicketStoreFixture : IDisposable
{
    private readonly ServiceProvider _services;
    public IDatabase Database { get; } = A.Fake<IDatabase>();
    public ISessionLedgerWriter Ledger { get; } = A.Fake<ISessionLedgerWriter>();
    public TestTimeProvider Clock { get; } = new();
    public RedisTicketStore Redis { get; }
    public PamTicketStore Store { get; }
    public PamSessionLifetime Lifetime { get; }

    public TicketStoreFixture()
    {
        var multiplexer = A.Fake<IConnectionMultiplexer>();
        A.CallTo(() => multiplexer.GetDatabase(A<int>._, A<object>._)).Returns(Database);
        A.CallTo(() => Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
            A<TimeSpan?>._, When.NotExists)).Returns(true);
        _services = new ServiceCollection()
            .AddScoped<ISessionLedgerWriter>(_ => Ledger)
            .BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        Redis = new RedisTicketStore(multiplexer, new EphemeralDataProtectionProvider(), Clock);
        Lifetime = new PamSessionLifetime(Options.Create(new PamSessionOptions
        {
            IdleTimeout = TimeSpan.FromMinutes(30),
            AbsoluteTimeout = TimeSpan.FromHours(8)
        }), Clock);
        Store = new PamTicketStore(Redis, _services.GetRequiredService<IServiceScopeFactory>(),
            Clock, Lifetime, NullLogger<PamTicketStore>.Instance);
    }

    public AuthenticationTicket StartedTicket()
    {
        var ticket = SessionTestData.Ticket(Clock.Now);
        Lifetime.Initialize(ticket.Properties);
        return ticket;
    }

    public async Task<string> SeedRenewableSessionAsync()
    {
        var existing = StartedTicket();
        existing.Properties.ExpiresUtc = existing.Properties.ExpiresUtc!.Value.AddMinutes(-1);
        RedisValue payload = default;
        A.CallTo(() => Database.StringSetAsync(A<RedisKey>._, A<RedisValue>._,
                A<TimeSpan?>._, When.NotExists))
            .Invokes(call => payload = call.GetArgument<RedisValue>(1)).Returns(true);
        var id = await Redis.StoreAsync(existing);
        A.CallTo(() => Database.StringGetAsync(A<RedisKey>._, CommandFlags.None)).Returns(payload);
        return id;
    }

    public void Dispose() => _services.Dispose();
}
