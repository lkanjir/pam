namespace Application.Principals;

/// <summary>Configured assignment counts; unavailable parents are reported separately and may overlap either state.</summary>
public sealed record PrincipalAssignmentCounts(long Active, long Inactive, long UnavailableParents);
