using System.ComponentModel.DataAnnotations;

namespace Application.Resources;

/// <summary>Cursor pagination and an optional filter for the current user's requestable resources.</summary>
public sealed record ResourceListQuery(
    [property: Range(1, 100)] int Limit = 20,
    ResourceCursor? Cursor = null,
    bool Requestable = false);
