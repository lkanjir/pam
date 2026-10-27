using System.Security.Claims;

namespace Api.Authentication;

public static class PamClaimTypes
{
    public const string PrincipalId = ClaimTypes.NameIdentifier;
    public const string PublicId = "pam_public_id";
    public const string DisplayName = "name";
    public const string Issuer = "pam_issuer";
    public const string Subject = "sub";
    public const string Role = "pam_role";
    public const string IdpSessionId = "sid";
}
