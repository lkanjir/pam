using System.ComponentModel.DataAnnotations;
using Api.Authentication;
using Application.AccessRequests;
using Application.Common.Pagination;
using Application.Sessions;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace Api.AccessRequests;

public static class AccessRequestEndpoints
{
    public static IEndpointRouteBuilder MapAccessRequestEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var requests = endpoints.MapGroup("/access-requests").WithTags("Access requests");
        requests.MapGet("/mine", ListMine)
            .WithName("AccessRequest.ListMine")
            .WithSummary("List the authenticated caller's access requests")
            .WithDescription("Returns only requests owned by the current PAM session, including denied requests "
                + "and history for retired resources. Uses descending public-ID cursor pagination. "
                + "Limit defaults to 20 and must be between 1 and 100. An empty result is an empty page.")
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
        requests.MapGet("/{requestId:guid}", GetMine)
            .WithName("AccessRequest.GetById")
            .WithSummary("Get an access request owned by the authenticated caller")
            .WithDescription("Returns the saved request and policy evaluation, current resource and entitlement "
                + "labels, and up to two initial submission audit summaries. Retired resources remain visible. "
                + "Policy is not reevaluated. Missing requests and requests owned by another user both return 404.")
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status500InternalServerError);
        requests.MapPost("", Submit)
            .WithName("AccessRequest.Create")
            .WithSummary("Submit an access request and evaluate Sprint 1 eligibility")
            .WithDescription("The requester comes from the PAM session. Resource and entitlement must be active "
                + "and belong together. Duration must be within the entitlement maximum; justification is required "
                + "(maximum 2000 characters), and a ticket is required when configured (maximum 100 characters). "
                + "Provide one Idempotency-Key header of 1–128 printable non-whitespace ASCII characters. "
                + "A new valid submission returns 201 with PendingApproval or Denied. Replaying the key with "
                + "the same normalized payload returns the original request with 200; a different payload returns 409. "
                + "This endpoint does not approve requests or grant access.")
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status401Unauthorized)
            .ProducesProblem(StatusCodes.Status409Conflict)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status500InternalServerError);

        return endpoints;
    }

    private static async Task<Results<Ok<CursorPage<AccessRequestSummaryResponse>>, UnauthorizedHttpResult>> ListMine(
        [AsParameters] AccessRequestListQuery query,
        HttpContext context,
        IAccessRequestService service,
        CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        var page = await service.ListMineAsync(identity.Id, query.Limit, query.Cursor, cancellationToken);
        return TypedResults.Ok(page);
    }

    private static async Task<Results<Ok<AccessRequestDetailsResponse>, NotFound, UnauthorizedHttpResult>> GetMine(
        Guid requestId,
        HttpContext context,
        IAccessRequestService service,
        CancellationToken cancellationToken)
    {
        if (!PamClaims.TryRead(context.User, out var identity))
        {
            return TypedResults.Unauthorized();
        }

        var request = await service.GetMineAsync(requestId, identity.Id, cancellationToken);
        return request is null ? TypedResults.NotFound() : TypedResults.Ok(request);
    }

    private static async Task<Results<Created<AccessRequestResponse>, Ok<AccessRequestResponse>,
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

        if (result.Kind == AccessRequestSubmissionKind.Conflict)
        {
            return TypedResults.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "The idempotency key was already used for a different request.",
                extensions: new Dictionary<string, object?> { ["code"] = "idempotency_conflict" });
        }

        if (result.Kind == AccessRequestSubmissionKind.Forbidden)
        {
            return TypedResults.Problem(statusCode: StatusCodes.Status403Forbidden);
        }

        var response = result.Request ?? throw new InvalidOperationException("Submission returned no request.");
        return result.Kind == AccessRequestSubmissionKind.Replayed
            ? TypedResults.Ok(response)
            : TypedResults.Created($"/api/access-requests/{response.Id}", response);
    }
}
