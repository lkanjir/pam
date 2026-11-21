using System.ComponentModel.DataAnnotations;

namespace Application.Principals;

/// <summary>A justification for changing one principal's entitlement eligibility.</summary>
public sealed record ChangeEligibilityRequest
{
    /// <summary>The required administrative audit reason, limited to 500 characters.</summary>
    [Required, MaxLength(500)]
    public string Reason { get; init; } = string.Empty;
}
