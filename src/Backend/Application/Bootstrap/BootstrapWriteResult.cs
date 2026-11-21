namespace Application.Bootstrap;

public enum BootstrapWriteKind
{
    Succeeded,
    Forbidden,
    RecentAuthenticationRequired,
    NotInitialized,
    PreconditionFailed,
    InvalidRequest
}

public sealed record BootstrapWriteResult(BootstrapWriteKind Kind, BootstrapStateResponse? State = null);
