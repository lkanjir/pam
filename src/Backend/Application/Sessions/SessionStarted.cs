using System.Net;

namespace Application.Sessions;

public sealed record SessionStarted(
    long PrincipalId,
    string SessionIdHash,
    string? IdpSessionId,
    DateTimeOffset CreatedAt,
    DateTimeOffset ExpectedExpiresAt,
    IPAddress? ClientIpAddress,
    string? UserAgent);