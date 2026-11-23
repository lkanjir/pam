namespace Application.Principals;

/// <summary>A consistent principal/role/assignment overview for explicit administrative review before enabling an account.</summary>
public sealed record PrincipalAuthorizationOverviewResponse(PrincipalResponse Principal, IReadOnlyList<string> Roles,
    PrincipalAssignmentCounts ResourceAccess, PrincipalAssignmentCounts Eligibility, PrincipalAssignmentCounts ApprovalAuthority)
{
    /// <summary>Server-generated links to the paginated assignment collections.</summary>
    public PrincipalAuthorizationLinks? Links { get; init; }
}
