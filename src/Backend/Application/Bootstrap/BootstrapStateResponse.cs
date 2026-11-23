using System.Text.Json.Serialization;

namespace Application.Bootstrap;

/// <summary>Reports the controlled installation handover state; reading never initializes it.</summary>
public sealed record BootstrapStateResponse(bool IsInitialized, bool IsPending, Guid? BootstrapPrincipalId,
    DateTimeOffset? InitializedAt, DateTimeOffset? CompletedAt, Guid? CompletedByPrincipalId)
{
    [JsonIgnore]
    public uint? Version { get; init; }
}
