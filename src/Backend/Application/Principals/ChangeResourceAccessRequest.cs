using System.ComponentModel.DataAnnotations;

namespace Application.Principals;

/// <summary>A justification for changing one resource-principal assignment.</summary>
public sealed record ChangeResourceAccessRequest
{
    /// <summary>The required administrative audit reason, limited to 500 characters.</summary>
    [Required, MaxLength(500)]
    public string Reason { get; init; } = string.Empty;
}
