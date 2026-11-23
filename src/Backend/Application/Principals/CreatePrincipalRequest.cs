using System.ComponentModel.DataAnnotations;

namespace Application.Principals;

/// <summary>Maps an externally verified Keycloak identity to a disabled PAM account; contains no credentials.</summary>
public sealed record CreatePrincipalRequest
{
    [Required, MaxLength(2048)]
    public required string Issuer { get; init; }
    [Required, MaxLength(255)]
    public required string Subject { get; init; }
    [Required, MaxLength(200)]
    public required string DisplayName { get; init; }
    [Required, MaxLength(500)]
    public required string Reason { get; init; }
}
