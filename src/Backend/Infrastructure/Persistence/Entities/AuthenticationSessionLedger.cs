using System.Net;

namespace Infrastructure.Persistence.Entities;

public sealed class AuthenticationSessionLedger
{
    public long Id { get; init; }
    public Guid PublicId { get; init; }
    public long PrincipalId { get; init; }
    public string SessionIdHash { get; init; } = string.Empty;
    public string? IdpSessionId { get; init; }
    public DateTime CreatedAt { get; init; }
    public DateTime ExpectedExpiresAt { get; init; }
    public DateTime? EndedAt { get; init; }
    public string? EndReason { get; init; }
    public IPAddress? ClientIpAddress { get; init; }
    public string? UserAgent { get; init; }
    public string? Browser { get; init; }
    public string? OperatingSystem { get; init; }
    public string? DeviceType { get; init; }
}
