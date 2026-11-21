namespace Application.Principals;

public enum PrincipalWriteKind
{
    Succeeded,
    Conflict,
    InvalidIdentity,
    InvalidRequest,
    Forbidden,
    RecentAuthenticationRequired,
    NotFound,
    PreconditionFailed,
    SelfChangeForbidden,
    LastAdmin
}

public sealed record PrincipalWriteResult(PrincipalWriteKind Kind, PrincipalResponse? Principal = null);
