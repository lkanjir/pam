using Api.Authentication;
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
        Store = new PamTicketStore(Redis, _services.GetRequiredService<IServiceScopeFactory>(),
            Clock, NullLogger<PamTicketStore>.Instance);
    }

    public void Dispose() => _services.Dispose();
}
