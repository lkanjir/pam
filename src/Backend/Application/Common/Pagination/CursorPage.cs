namespace Application.Common.Pagination;

public record CursorPage<T>(IReadOnlyList<T> Items, string? NextCursor)
{
    public bool HasNextPage => NextCursor is not null;
}
