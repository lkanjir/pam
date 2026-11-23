using System.Text.Json.Serialization;

namespace Application.Resources;

/// <summary>A managed resource, optionally including the caller's requestable entitlements.</summary>
public sealed record ResourceResponse(
    Guid Id,
    string Name,
    string? Description,
    string ResourceType,
    string Environment,
    bool IsActive,
    DateTime CreatedAt,
    DateTime ModifiedAt)
{
    /// <summary>Storage concurrency token used for HTTP ETags, excluded from the JSON contract.</summary>
    [JsonIgnore]
    public uint Version { get; init; }

    /// <summary>The caller's available entitlements, included only for requestable-resource lists.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<RequestableEntitlementResponse>? Entitlements { get; init; }
}
