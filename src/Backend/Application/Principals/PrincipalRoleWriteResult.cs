namespace Application.Principals;

/// <summary>The authorized outcome and current explicit roles after a successful command.</summary>
public sealed record PrincipalRoleWriteResult(PrincipalWriteKind Kind, PrincipalRolesResponse? Roles = null);
