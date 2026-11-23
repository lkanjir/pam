namespace Application.Principals;

/// <summary>An authorized eligibility outcome and the principal aggregate version after success.</summary>
public sealed record EligibilityWriteResult(PrincipalWriteKind Kind, uint? Version = null);
