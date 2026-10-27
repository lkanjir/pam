using System.Net;

namespace Application.Sessions;

public sealed record SessionRequestMetadata(
    IPAddress? ClientIpAddress,
    string? UserAgent,
    string CorrelationId);
