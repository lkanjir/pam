using System.ComponentModel.DataAnnotations;
using Api.Authentication;
using Application.AccessRequests;
using Application.Sessions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Api.AccessRequests;

public static class AccessRequestEndpoints
{
    public static IEndpointRouteBuilder MapAccessRequestEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var requests = endpoints.MapGroup("/access-requests").WithTags("Access requests");
        requests.MapPost("", Submit)
            .WithName("AccessRequest.Create")
            .WithSummary("Submit an access request and evaluate Sprint 1 eligibility")
            .WithDescription("The requester comes from the PAM session. Resource and entitlement must be active "
                + "and belong together. Duration must be within the entitlement maximum; justification is required "
                + "(maximum 2000 characters), and a ticket is required when configured (maximum 100 characters). "
                + "Provide one Idempotency-Key header of 1–128 printable non-whitespace ASCII characters. "
                + "Use a unique key for each submission. A valid submission returns 201 with PendingApproval or Denied. "
                + "This endpoint does not approve requests or grant access.")
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        return endpoints;
    }

    private static async Task<Results<Created<AccessRequestResponse>,
        ValidationProblem, ProblemHttpResult, UnauthorizedHttpResult>> Submit(
        CreateAccessRequestRequest request,
        [FromHeader(Name = "Idempotency-Key"), Required, StringLength(128, MinimumLength = 1)] string? idempotencyKey,
        HttpContext context,
        IAccessRequestService service,
        CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        if (string.IsNullOrWhiteSpace(idempotencyKey)
            || context.Request.Headers["Idempotency-Key"].Count != 1
            || idempotencyKey.Length > 128
            || idempotencyKey.Any(character => character is < '!' or > '~'))
        {
            return TypedResults.ValidationProblem(new Dictionary<string, string[]>
            {
                ["Idempotency-Key"] = ["Provide one key of 1–128 printable non-whitespace ASCII characters."]
            });
        }

        var requester = new PrincipalSnapshot(
            identity.Id, identity.PublicId, identity.DisplayName, identity.Issuer, identity.Subject);
        var result = await service.SubmitAsync(
            request, idempotencyKey, requester, context.TraceIdentifier, cancellationToken);

        if (result.Kind == AccessRequestSubmissionKind.Invalid)
        {
            return TypedResults.ValidationProblem(result.Errors);
        }

        if (result.Kind == AccessRequestSubmissionKind.Forbidden)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden);
        }

        var response = result.Request ?? throw new InvalidOperationException("Submission returned no request.");
        return TypedResults.Created($"/api/access-requests/{response.Id}", response);
    }
}
