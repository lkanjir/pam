namespace Infrastructure.Authentication;

/// <summary>A resumable native Redis hash scan; page size remains fixed across passes.</summary>
public sealed record SessionLeasePosition(long Cursor = 0, int PageOffset = 0);

public sealed record SessionLeasePage(IReadOnlyList<string> SessionIdHashes, SessionLeasePosition Next);
