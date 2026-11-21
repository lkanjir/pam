namespace Application.Principals;

/// <summary>An authorized assignment outcome and the principal aggregate version after success.</summary>
public sealed record ResourceAccessWriteResult(PrincipalWriteKind Kind, uint? Version = null);
