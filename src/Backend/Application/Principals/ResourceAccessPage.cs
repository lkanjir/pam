using Application.Common.Pagination;

namespace Application.Principals;

/// <summary>A bounded administrative page and its consistent principal aggregate concurrency token.</summary>
public sealed record ResourceAccessPage(CursorPage<ResourceAccessResponse> Page, uint Version);
