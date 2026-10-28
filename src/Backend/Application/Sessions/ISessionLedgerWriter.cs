namespace Application.Sessions;

public interface ISessionLedgerWriter
{
    Task RecordStartedAsync(SessionStarted session, CancellationToken cancellationToken = default);

    Task RecordRenewedAsync(
        string sessionIdHash,
        DateTimeOffset expectedExpiresAt,
        CancellationToken cancellationToken = default);

    Task RecordEndedAsync(
        string sessionIdHash,
        DateTimeOffset endedAt,
        string reason,
        string correlationId,
        CancellationToken cancellationToken = default);
}
