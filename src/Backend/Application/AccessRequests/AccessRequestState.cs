namespace Application.AccessRequests;

public enum AccessRequestState
{
    Denied,
    PendingApproval,
    Approved,
    Rejected,
    Cancelled,
    Expired
}

public static class AccessRequestStates
{
    public static string ToCode(this AccessRequestState state) => state switch
    {
        AccessRequestState.Denied => "Denied",
        AccessRequestState.PendingApproval => "PendingApproval",
        AccessRequestState.Approved => "Approved",
        AccessRequestState.Rejected => "Rejected",
        AccessRequestState.Cancelled => "Cancelled",
        AccessRequestState.Expired => "Expired",
        _ => throw new ArgumentOutOfRangeException(nameof(state))
    };

    public static AccessRequestState Parse(string code) => code switch
    {
        "Denied" => AccessRequestState.Denied,
        "PendingApproval" => AccessRequestState.PendingApproval,
        "Approved" => AccessRequestState.Approved,
        "Rejected" => AccessRequestState.Rejected,
        "Cancelled" => AccessRequestState.Cancelled,
        "Expired" => AccessRequestState.Expired,
        _ => throw new ArgumentException("Unknown request state code.", nameof(code))
    };

    public static bool CanTransitionTo(this AccessRequestState current, AccessRequestState next) =>
        current == AccessRequestState.PendingApproval
        && next is AccessRequestState.Approved or AccessRequestState.Rejected
            or AccessRequestState.Cancelled or AccessRequestState.Expired;
}
