namespace Application.Resources;

/// <summary>An available entitlement and the constraints needed to submit an access request.</summary>
public sealed record RequestableEntitlementResponse(
    Guid Id,
    string Code,
    string Name,
    int MaxDurationMinutes,
    bool RequiresApproval,
    bool RequiresTicket);
