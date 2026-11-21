using System.ComponentModel.DataAnnotations;

namespace Application.Principals;

/// <summary>Required administrative reason for an explicit account-status command.</summary>
public sealed record ChangePrincipalStatusRequest
{
    [Required, MaxLength(500)]
    public required string Reason { get; init; }
}
