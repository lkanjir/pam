using Infrastructure.Authentication;

namespace Infrastructure.Sessions;

/// <summary>A bounded sweep cursor; a fixed ceiling prevents new logins from starving older sessions.</summary>
public sealed record SessionReconciliationPosition(long AfterId = 0, long ThroughId = 0)
{
    public SessionLeasePosition Leases { get; init; } = new();
}
