namespace Application.Principals;

public enum PrincipalWriteKind
{
    Succeeded,
    Conflict,
    InvalidIdentity,
    Forbidden,
    RecentAuthenticationRequired
}

public sealed record PrincipalWriteResult(PrincipalWriteKind Kind, PrincipalResponse? Principal = null);
