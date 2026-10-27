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
        if (userAgent?.Length > 2048) userAgent = userAgent[..2048];

        var sessionIdHash = SessionIdentifier.Hash(sessionId);

        return new SessionStarted(
            PrincipalId: identity.Id,
            SessionIdHash: sessionIdHash,
            IdpSessionId: identity.IdpSessionId,
            CreatedAt: createdAt,
            ExpectedExpiresAt: expiresAt,
            ClientIpAddress: context?.Connection.RemoteIpAddress,
            UserAgent: userAgent,
            PrincipalPublicId: identity.PublicId.ToString(),
            DisplayName: identity.DisplayName,
            Issuer: identity.Issuer,
            Subject: identity.Subject,
            CorrelationId: context?.TraceIdentifier ?? Guid.NewGuid().ToString("N"));
    }
}