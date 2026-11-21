namespace Application.Resources;

/// <summary>Administrative configuration of an entitlement, independent of requester eligibility.</summary>
public sealed record ManagedEntitlementResponse(Guid Id, string Code, string Name, int MaxDurationMinutes,
    bool RequiresApproval, bool RequiresTicket, bool IsActive);
