namespace Application.AccessRequests;

public sealed record AccessRequestPolicyResult(
    AccessRequestPolicyDecision? Decision,
    string ReasonCode,
    string Explanation)
{
    public Dictionary<string, string[]> Errors { get; init; } = [];
}

public static class AccessRequestPolicy
{
    public const string Code = "sprint1.eligibility";
    public const int Version = 1;

    public static AccessRequestPolicyResult Evaluate(
        CreateAccessRequestRequest request,
        int maxDurationMinutes,
        bool requiresTicket,
        bool isEligible)
    {
        var errors = new Dictionary<string, string[]>();
        if (request.RequestedDurationMinutes <= 0 || request.RequestedDurationMinutes > maxDurationMinutes)
        {
            errors[nameof(request.RequestedDurationMinutes)] =
                ["Duration must be positive and within the entitlement maximum."];
        }

        if (requiresTicket && string.IsNullOrWhiteSpace(request.TicketReference))
        {
            errors[nameof(request.TicketReference)] = ["A ticket reference is required for this entitlement."];
        }

        if (errors.Count > 0)
        {
            return new AccessRequestPolicyResult(
                null, "invalid_request", "The request does not satisfy entitlement constraints.")
            {
                Errors = errors
            };
        }

        // Sprint 1 never auto-approves or provisions access, even for an entitlement without an approval flag.
        return isEligible
            ? new(AccessRequestPolicyDecision.RequireApproval, "approval_required", "The request requires manual approval.")
            : new(AccessRequestPolicyDecision.Deny, "not_eligible", "The requester is not eligible for this entitlement.");
    }
}
