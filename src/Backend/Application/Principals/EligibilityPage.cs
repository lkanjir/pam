using Application.Common.Pagination;

namespace Application.Principals;

/// <summary>A bounded eligibility page and its consistent principal aggregate concurrency token.</summary>
public sealed record EligibilityPage(CursorPage<EligibilityResponse> Page, uint Version);
