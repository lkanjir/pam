using System.ComponentModel.DataAnnotations;

namespace Application.Resources;

public sealed record ResourceListQuery
{
    [Range(1, 100)] public int Limit { get; init; } = 20;

    public string? Cursor { get; init; }
}
