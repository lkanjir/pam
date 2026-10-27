using Application.Sessions;
using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication;

internal static class SessionStartedFactory
{
    public static SessionStarted Create(string sessionId, AuthenticationTicket ticket, HttpContext? context,
        DateTimeOffset createdAt)
    {
        if (!PamClaims.TryRead(ticket.Principal, out var identity))
            throw new InvalidOperationException("Authentication ticket must contain a valid PAM identity.");

        var expiresAt = ticket.Properties.ExpiresUtc ??
                        throw new InvalidOperationException("Authentication ticket must have an expiration time.");

        var userAgent = context?.Request.Headers.UserAgent.ToString();
        if (userAgent?.Length > 2048)
            userAgent = userAgent[..2048];

        var sessionIdHash = SessionIdentifier.Hash(sessionId);

        return new SessionStarted(
            Principal: new PrincipalSnapshot(
                identity.Id, identity.PublicId, identity.DisplayName, identity.Issuer, identity.Subject),
            SessionIdHash: sessionIdHash,
            IdpSessionId: identity.IdpSessionId,
            CreatedAt: createdAt,
            ExpectedExpiresAt: expiresAt,
            Request: new SessionRequestMetadata(
                context?.Connection.RemoteIpAddress,
                userAgent,
                context?.TraceIdentifier ?? Guid.NewGuid().ToString("N")));
    }
}
