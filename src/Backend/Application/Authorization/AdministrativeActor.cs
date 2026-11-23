using Application.Sessions;

namespace Application.Authorization;

/// <summary>Server-derived identity and the original validated OIDC authentication instant.</summary>
public sealed record AdministrativeActor(PrincipalSnapshot Principal, DateTimeOffset? AuthenticatedAt);
