using Application.Common.Diagnostics;
using Application.Identity;
using Application.Authorization;
using Infrastructure.Authentication;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Mvc;

namespace Api.Authentication;

public sealed class PamOpenIdConnectEvents(
    IPrincipalIdentityReader principalReader,
    IProblemDetailsService problemDetails,
    ILogger<PamOpenIdConnectEvents> logger,
    TimeProvider timeProvider,
    ISessionTicketStore tickets,
    SessionTerminator terminator) : OpenIdConnectEvents
{
    private static readonly Action<ILogger, string?, string, string?, string, Exception?> LogLoginFailure =
        LoggerMessage.Define<string?, string, string?, string>(
            LogLevel.Error,
            new EventId(0),
            "OIDC login failed. Error type: {ErrorType}, correlation: {CorrelationId}, "
            + "database code: {DatabaseCode}, location: {ErrorLocation}");

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

        PamReauthentication.Binding? binding = null;
        bool reauth = PamReauthentication.IsRequested(context.Properties);
        if (reauth && (!PamReauthentication.TryRead(context.Properties, out binding) || binding is null
            || binding.Issuer != issuer || binding.Subject != subject))
        {
            context.HandleResponse();
            await WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "Reauthentication was not accepted.");
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
        var authenticatedAt = context.Principal is { } tokenPrincipal
            ? PamAuthenticationTime.Read(tokenPrincipal, "auth_time") : null;
        if (reauth && (binding is null || binding.PrincipalId != principal.PublicId
            || !RecentAuthentication.IsSatisfied(authenticatedAt, timeProvider.GetUtcNow())))
        {
            context.HandleResponse();
            await WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "Reauthentication was not accepted.");
            return;
        }

        context.Principal = PamClaims.Create(principal, issuer, subject, idpSessionId, authenticatedAt);
    }

    public override async Task TicketReceived(TicketReceivedContext context)
    {
        if (!PamReauthentication.IsRequested(context.Properties))
        {
            return;
        }

        if (!PamReauthentication.TryRead(context.Properties, out var binding) || binding is null
            || context.Principal is null || !PamClaims.TryRead(context.Principal, out var identity)
            || identity.PublicId != binding.PrincipalId || identity.Issuer != binding.Issuer || identity.Subject != binding.Subject
            || !RecentAuthentication.IsSatisfied(PamAuthenticationTime.Read(context.Principal), timeProvider.GetUtcNow()))
        {
            context.HandleResponse();
            await WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "Reauthentication was not accepted.");
            return;
        }

        // TicketReceived follows the framework's token, state and nonce validation.
        // A conditional Redis close binds the successful replacement to this still-active original session.
        context.HttpContext.RequestAborted.ThrowIfCancellationRequested();
        var observed = await tickets.ObserveAsync(binding.SessionIdHash);
        if (!await terminator.TryEndForReauthenticationAsync(binding.SessionIdHash, observed,
            context.HttpContext.TraceIdentifier, context.HttpContext.RequestAborted))
        {
            context.HandleResponse();
            await WriteProblemAsync(context.HttpContext, StatusCodes.Status403Forbidden, "The original session is no longer available.");
            return;
        }

        PamReauthentication.Clear(context.Properties);
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

        var diagnostic = context.Failure is { } failure ? ExceptionDiagnostics.Capture(failure) : null;
        LogLoginFailure(
            logger,
            diagnostic?.ErrorType,
            context.HttpContext.TraceIdentifier,
            diagnostic?.DatabaseCode,
            diagnostic?.Location ?? "unavailable",
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
