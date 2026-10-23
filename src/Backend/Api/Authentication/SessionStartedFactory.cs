using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using Application.Sessions;
using Microsoft.AspNetCore.Authentication;

namespace Api.Authentication;

internal static class SessionStartedFactory
{
    public static SessionStarted Create(string sessionId, AuthenticationTicket ticket, HttpContext? context,
        DateTimeOffset createdAt)
    {
        var principalIdClaim = ticket.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        if (!long.TryParse(principalIdClaim, NumberStyles.None, CultureInfo.InvariantCulture, out var principalId) ||
            principalId <= 0)
        {
            throw new InvalidOperationException("Authentication ticket must identify a local principal.");
        }

        var expiresAt = ticket.Properties.ExpiresUtc ??
                        throw new InvalidOperationException("Authentication ticket must have an expiration time.");

        var userAgent = context?.Request.Headers.UserAgent.ToString();
        if (userAgent?.Length > 2048) userAgent = userAgent[..2048];

        var sessionIdHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sessionId)));

        return new SessionStarted(
            PrincipalId: principalId,
            SessionIdHash: sessionIdHash,
            IdpSessionId: ticket.Principal.FindFirst("sid")?.Value,
            CreatedAt: createdAt,
            ExpectedExpiresAt: expiresAt,
            ClientIpAddress: context?.Connection.RemoteIpAddress,
            UserAgent: userAgent);
    }
}