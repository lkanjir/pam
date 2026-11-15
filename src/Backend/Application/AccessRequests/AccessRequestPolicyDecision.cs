namespace Application.AccessRequests;

public enum AccessRequestPolicyDecision
{
    Deny,
    RequireApproval
}

public static class AccessRequestPolicyDecisions
{
    // Keep stored/API codes stable while separating policy semantics from lifecycle states.
    public static string ToCode(this AccessRequestPolicyDecision decision) => decision switch
    {
        AccessRequestPolicyDecision.Deny => "Denied",
        AccessRequestPolicyDecision.RequireApproval => "PendingApproval",
        _ => throw new ArgumentOutOfRangeException(nameof(decision))
    };

    public static AccessRequestPolicyDecision Parse(string code) => code switch
    {
        "Denied" => AccessRequestPolicyDecision.Deny,
        "PendingApproval" => AccessRequestPolicyDecision.RequireApproval,
        _ => throw new ArgumentException("Unknown policy decision code.", nameof(code))
    };

    public static AccessRequestState InitialState(this AccessRequestPolicyDecision decision) => decision switch
    {
        AccessRequestPolicyDecision.Deny => AccessRequestState.Denied,
        AccessRequestPolicyDecision.RequireApproval => AccessRequestState.PendingApproval,
        _ => throw new ArgumentOutOfRangeException(nameof(decision))
    };
}
