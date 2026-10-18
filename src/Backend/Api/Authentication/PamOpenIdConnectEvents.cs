using System.Globalization;
using System.Security.Claims;
using Application.Identity;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Api.Authentication;

public sealed class PamOpenIdConnectEvents(IPrincipalIdentityReader principalReader) : OpenIdConnectEvents
{
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        var issuer = context.SecurityToken.Issuer;
        var subject = context.Principal?.FindFirst("sub")?.Value;

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            context.Fail("Required identity claims are missing");
            return;
        }

        var principal = await principalReader.FindAsync(issuer, subject, context.HttpContext.RequestAborted);
        if (principal is null || !principal.IsEnabled)
        {
            context.Fail("PAM access is not allowed");
            return;
        }

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, principal.Id.ToString(CultureInfo.InvariantCulture)),
            new("pam_public_id", principal.PublicId.ToString()),
            new("name", principal.DisplayName),
            new("pam_issuer", issuer),
            new("sub", subject)
        };
        claims.AddRange(principal.Roles.Select(role => new Claim("pam_role", role)));

        var idpSessionId = context.Principal?.FindFirst("sid")?.Value;
        if (!string.IsNullOrWhiteSpace(idpSessionId)) claims.Add(new Claim("sid", idpSessionId));

        var identity = new ClaimsIdentity(claims, authenticationType: CookieAuthenticationDefaults.AuthenticationScheme,
            nameType: "name", roleType: "pam_role");

        context.Principal = new ClaimsPrincipal(identity);
    }
}