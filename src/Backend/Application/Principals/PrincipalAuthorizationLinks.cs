namespace Application.Principals;

/// <summary>Bounded administrative collections used to inspect a principal's retained assignments.</summary>
public sealed record PrincipalAuthorizationLinks(string Roles, string ResourceAccess, string Eligibility, string ApprovalAuthority);
