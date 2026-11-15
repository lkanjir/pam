using System.Text.Json.Serialization;

namespace Application.Sessions;

/// <summary>A replayable session completion without a cookie, ticket or raw session identifier.</summary>
public sealed record PendingSessionEnd(
    [property: JsonRequired] string SessionIdHash,
    [property: JsonRequired] DateTimeOffset EndedAt,
    [property: JsonRequired] string Reason,
    [property: JsonRequired] string CorrelationId,
    DateTimeOffset? ExpectedExpiresAt = null);
