using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Claims;
using Application.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Api.Authentication;

public static class PamClaims
{
    public static ClaimsPrincipal Create(PrincipalIdentity principal, string issuer, string subject,
        string? idpSessionId)
    {
        var claims = new List<Claim>
        {
            new(PamClaimTypes.PrincipalId, principal.Id.ToString(CultureInfo.InvariantCulture)),
            new(PamClaimTypes.PublicId, principal.PublicId.ToString()),
            new(PamClaimTypes.DisplayName, principal.DisplayName),
            new(PamClaimTypes.Issuer, issuer),
            new(PamClaimTypes.Subject, subject)
        };
        claims.AddRange(principal.Roles.Select(role => new Claim(PamClaimTypes.Role, role)));
        if (!string.IsNullOrWhiteSpace(idpSessionId))
            claims.Add(new Claim(PamClaimTypes.IdpSessionId, idpSessionId));
        return new ClaimsPrincipal(new ClaimsIdentity(claims,
            CookieAuthenticationDefaults.AuthenticationScheme, PamClaimTypes.DisplayName, PamClaimTypes.Role));
    }

    public static bool TryRead(ClaimsPrincipal principal, [NotNullWhen(true)] out PamUserIdentity? identity)
    {
        identity = null;
        var issuer = principal.FindFirst(PamClaimTypes.Issuer)?.Value;
        var subject = principal.FindFirst(PamClaimTypes.Subject)?.Value;
        var name = principal.FindFirst(PamClaimTypes.DisplayName)?.Value;
        if (!long.TryParse(principal.FindFirst(PamClaimTypes.PrincipalId)?.Value,
                NumberStyles.None, CultureInfo.InvariantCulture, out var id) || id <= 0
            || !Guid.TryParse(principal.FindFirst(PamClaimTypes.PublicId)?.Value, out var publicId)
            || string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject) || name is null)
            return false;

        identity = new PamUserIdentity(id, publicId, name, issuer, subject,
            principal.FindAll(PamClaimTypes.Role).Select(claim => claim.Value).ToArray(),
            principal.FindFirst(PamClaimTypes.IdpSessionId)?.Value);
        return true;
    }
}
