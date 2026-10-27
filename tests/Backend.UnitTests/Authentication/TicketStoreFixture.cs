using Api.Authentication;
using Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Application.Sessions;
using Backend.Tests.Support;
using FakeItEasy;
using Infrastructure.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Backend.UnitTests.Authentication;

internal sealed class TicketStoreFixture : IDisposable
{
    private readonly ServiceProvider _services;
    public static readonly string SessionId = new('A', 64);
    public ISessionTicketStore Tickets { get; } = A.Fake<ISessionTicketStore>();
    public ISessionLedgerWriter Ledger { get; } = A.Fake<ISessionLedgerWriter>();
    public TestTimeProvider Clock { get; } = new();
    public PamTicketStore Store { get; }
    public PamSessionLifetime Lifetime { get; }

    public TicketStoreFixture()
    {
        A.CallTo(() => Tickets.StoreAsync(A<AuthenticationTicket>._)).Returns(SessionId);
        _services = new ServiceCollection()
            .AddScoped<ISessionLedgerWriter>(_ => Ledger)
            .BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        Lifetime = new PamSessionLifetime(Options.Create(new PamSessionOptions
        {
            IdleTimeout = TimeSpan.FromMinutes(30),
            AbsoluteTimeout = TimeSpan.FromHours(8)
        }), Clock);
        Store = new PamTicketStore(Tickets, _services.GetRequiredService<IServiceScopeFactory>(),
            Clock, Lifetime, NullLogger<PamTicketStore>.Instance);
    }

    public AuthenticationTicket StartedTicket()
    {
        var ticket = SessionTestData.Ticket(Clock.Now);
        Lifetime.Initialize(ticket.Properties);
        return ticket;
    }

    public void Dispose() => _services.Dispose();
}
