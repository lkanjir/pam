namespace Application.Principals;

/// <summary>A retained entitlement eligibility rule and the current status of its resource and entitlement.</summary>
public sealed record EligibilityResponse(Guid Id, Guid ResourceId, string ResourceName, Guid EntitlementId,
    string EntitlementCode, string EntitlementName, bool IsEnabled, bool IsResourceActive,
    bool IsResourceRetired, bool IsEntitlementActive, DateTimeOffset CreatedAt);
