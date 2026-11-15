using System.ComponentModel.DataAnnotations;

namespace Application.AccessRequests;

/// <summary>Cursor pagination for the authenticated caller's requests, in descending public-ID order.</summary>
public sealed record AccessRequestListQuery(
    [property: Range(1, 100)] int Limit = 20,
    AccessRequestCursor? Cursor = null);
