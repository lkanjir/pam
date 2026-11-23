using System.ComponentModel.DataAnnotations;

namespace Application.Bootstrap;

/// <summary>The permanent administrator's justification for terminal bootstrap retirement.</summary>
public sealed record CompleteBootstrapRequest
{
    [Required, MaxLength(500)]
    public required string Reason { get; init; }
}
