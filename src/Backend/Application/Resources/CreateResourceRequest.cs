using System.ComponentModel.DataAnnotations;

namespace Application.Resources;

public sealed record CreateResourceRequest
{
    [Required]
    [StringLength(200)]
    public required string Name { get; init; }

    [StringLength(2000)]
    public string? Description { get; init; }

    [Required]
    [StringLength(50)]
    public required string ResourceType { get; init; }

    [Required]
    [StringLength(50)]
    public required string Environment { get; init; }

    public bool IsActive { get; init; } = true;
};
