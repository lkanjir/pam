using Application.Identity;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Api.Authentication;

public sealed class PamOpenIdConnectEvents(IPrincipalIdentityReader principalReader) : OpenIdConnectEvents
{
    public override async Task TokenValidated(TokenValidatedContext context)
    {
        var issuer = context.SecurityToken.Issuer;
        var subject = context.Principal?.FindFirst(PamClaimTypes.Subject)?.Value;

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

        var idpSessionId = context.Principal?.FindFirst(PamClaimTypes.IdpSessionId)?.Value;
        context.Principal = PamClaims.Create(principal, issuer, subject, idpSessionId);
    }
}
