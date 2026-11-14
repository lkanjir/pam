using Application.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace Api.Authentication;

public sealed class PamOpenIdConnectEvents(
    IPrincipalIdentityReader principalReader,
    IProblemDetailsService problemDetails,
    ILogger<PamOpenIdConnectEvents> logger) : OpenIdConnectEvents
{
    private static readonly Action<ILogger, string?, string, Exception?> LogLoginFailure =
        LoggerMessage.Define<string?, string>(
            LogLevel.Error,
            new EventId(0),
            "OIDC login failed. Error type: {ErrorType}, correlation: {CorrelationId}");

    public override async Task TokenValidated(TokenValidatedContext context)
    {
        string issuer = context.SecurityToken.Issuer;
        string? subject = context.Principal?.FindFirst(PamClaimTypes.Subject)?.Value;

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(subject))
        {
            context.HandleResponse();

            await WriteProblemAsync(
                context.HttpContext,
                StatusCodes.Status401Unauthorized,
                "The login response is invalid");

            return;
        }

        var principal = await principalReader.FindAsync(issuer, subject, context.HttpContext.RequestAborted);
        if (principal is null || !principal.IsEnabled)
        {
            context.HandleResponse();

            await WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "Access is not allowed.");
            return;
        }

        var idpSessionId = context.Principal?.FindFirst(PamClaimTypes.IdpSessionId)?.Value;
        context.Principal = PamClaims.Create(principal, issuer, subject, idpSessionId);
    }

    public override async Task AccessDenied(AccessDeniedContext context)
    {
        context.HandleResponse();

        await WriteProblemAsync(
            context.HttpContext,
            StatusCodes.Status403Forbidden,
            "Login was denied by the identity provider");
    }

    public override async Task RemoteFailure(RemoteFailureContext context)
    {
        context.HandleResponse();

        if (context.HttpContext.RequestAborted.IsCancellationRequested)
        {
            return;
        }

        LogLoginFailure(
            logger,
            context.Failure?.GetType().FullName,
            context.HttpContext.TraceIdentifier,
            null);

        await WriteProblemAsync(context.HttpContext, StatusCodes.Status500InternalServerError);
    }

    private async Task WriteProblemAsync(HttpContext context, int status, string? title = null)
    {
        if (context.RequestAborted.IsCancellationRequested)
        {
            return;
        }

        await problemDetails.WriteAsync(
            new ProblemDetailsContext
            {
                HttpContext = context,
                ProblemDetails = new ProblemDetails { Status = status, Title = title, }
            });
    }
}
