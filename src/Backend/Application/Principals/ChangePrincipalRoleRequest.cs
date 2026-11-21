using System.ComponentModel.DataAnnotations;

namespace Application.Principals;

/// <summary>The justification for changing one explicit role assignment.</summary>
public sealed record ChangePrincipalRoleRequest
{
    /// <summary>A required audit reason, limited to 500 characters.</summary>
    [Required, MaxLength(500)]
    public string Reason { get; init; } = string.Empty;
}
