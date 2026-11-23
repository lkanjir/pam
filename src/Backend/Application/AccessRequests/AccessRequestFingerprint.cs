using System.Security.Cryptography;
using System.Text.Json;

namespace Application.AccessRequests;

/// <summary>Versioned submission fingerprints; v1's payload shape is independent of the HTTP DTO.</summary>
public static class AccessRequestFingerprint
{
    private const string Version1Prefix = "v1:";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string CreateV1(CreateAccessRequestRequest normalized)
    {
        // This persisted contract is frozen. New semantic fields require a new fingerprint version.
        var payload = new PayloadV1(normalized.ResourceId, normalized.EntitlementId,
            normalized.RequestedDurationMinutes, normalized.Justification, normalized.TicketReference);
        return Version1Prefix + Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions)));
    }

    public static bool IsMatch(string? stored, string fingerprint)
    {
        if (!fingerprint.StartsWith(Version1Prefix, StringComparison.Ordinal) || fingerprint.Length != 67)
        {
            return false;
        }

        // Before explicit versioning, the exact same v1 JSON shape was stored as a bare SHA-256 hex digest.
        return string.Equals(stored, fingerprint, StringComparison.Ordinal)
            || (stored is { Length: 64 } && string.Equals(stored, fingerprint[Version1Prefix.Length..], StringComparison.Ordinal));
    }

    private sealed record PayloadV1(Guid ResourceId, Guid EntitlementId, int RequestedDurationMinutes,
        string Justification, string? TicketReference);
}
