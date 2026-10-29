using System.ComponentModel.DataAnnotations;

namespace Application.Resources;

public sealed record ResourceListQuery(
    [Range(1, 100)] int Limit = 20,
    ResourceCursor? Cursor = null);
