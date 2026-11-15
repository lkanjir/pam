namespace Application.Sessions;

/// <summary>A non-secret observation of a ticket and its last recorded lease.</summary>
public sealed record SessionObservation(
    bool HasTicket,
    DateTimeOffset? TicketExpiresAt,
    DateTimeOffset? LeaseExpiresAt,
    string? LeaseVersion)
{
    public PendingSessionEnd? PendingEnd { get; init; }
}
