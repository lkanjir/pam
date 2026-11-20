using Api.Authentication;
using Application.Identity;
using Application.Sessions;
using FakeItEasy;
using Infrastructure.Authentication;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

namespace Backend.UnitTests.Authentication;

internal static class OidcEventsFixture
{
    public static PamOpenIdConnectEvents Create(IPrincipalIdentityReader reader, IProblemDetailsService problems)
    {
        var tickets = A.Fake<ISessionTicketStore>();
        var terminator = new SessionTerminator(tickets, A.Fake<ISessionLedgerWriter>(), TimeProvider.System,
            NullLogger<SessionTerminator>.Instance);
        return new PamOpenIdConnectEvents(reader, problems, NullLogger<PamOpenIdConnectEvents>.Instance,
            TimeProvider.System, tickets, terminator);
    }
}
