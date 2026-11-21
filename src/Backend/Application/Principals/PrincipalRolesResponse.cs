using System.Text.Json.Serialization;

namespace Application.Principals;

/// <summary>The explicitly assigned, known PAM bundles, without inherited roles.</summary>
public sealed record PrincipalRolesResponse(Guid PrincipalId, IReadOnlyList<string> Roles)
{
    /// <summary>Principal aggregate concurrency token, exposed only through ETag.</summary>
    [JsonIgnore]
    public uint Version { get; init; }
}
