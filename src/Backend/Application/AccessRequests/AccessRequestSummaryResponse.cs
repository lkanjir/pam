namespace Application.AccessRequests;

/// <summary>A request owned by the caller, including its resource and entitlement labels.</summary>
public sealed record AccessRequestSummaryResponse(
    Guid Id,
    Guid ResourceId,
    string ResourceName,
    Guid EntitlementId,
    string EntitlementName,
    int RequestedDurationMinutes,
    string State,
    DateTimeOffset CreatedAt);
