using Microsoft.AspNetCore.Authorization;

namespace Api.Authorization;

public sealed record PamBootstrapOperationRequirement(string Permission) : IAuthorizationRequirement;
