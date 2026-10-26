using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Api.Errors;

// API and OIDC failures use the same JSON contract, including browser navigation.
public sealed class PamProblemDetailsWriter : IProblemDetailsWriter
{
    public bool CanWrite(ProblemDetailsContext context) => true;

    public ValueTask WriteAsync(ProblemDetailsContext context)
    {
        var http = context.HttpContext;
        var problem = context.ProblemDetails;
        var status = problem.Status ?? http.Response.StatusCode;
        problem.Status = status;
        problem.Type ??= "about:blank";
        problem.Title ??= ReasonPhrases.GetReasonPhrase(status);
        problem.Extensions.TryAdd("code", status switch
        {
            400 => "bad_request",
            401 => "authentication_required",
            403 => "access_denied",
            404 => "not_found",
            405 => "method_not_allowed",
            409 => "conflict",
            415 => "unsupported_media_type",
            429 => "too_many_requests",
            500 => "internal_error",
            503 => "dependency_unavailable",
            _ => "http_error"
        });
        problem.Extensions["correlationId"] = http.TraceIdentifier;
        http.Response.StatusCode = status;
        http.Response.Headers.CacheControl = "no-store";

        return new ValueTask(http.Response.WriteAsJsonAsync(problem, problem.GetType(),
            options: null, contentType: "application/problem+json",
            cancellationToken: http.RequestAborted));
    }
}
