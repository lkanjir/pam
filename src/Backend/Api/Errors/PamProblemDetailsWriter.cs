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
        int status = problem.Status ?? http.Response.StatusCode;

        problem.Status = status;
        problem.Type ??= "about:blank";
        problem.Title ??= ReasonPhrases.GetReasonPhrase(status);
        problem.Extensions["correlationId"] = http.TraceIdentifier;

        http.Response.StatusCode = status;
        http.Response.Headers.CacheControl = "no-store";

        return new ValueTask(
            http.Response.WriteAsJsonAsync(
                problem,
                problem.GetType(),
                options: null,
                contentType: "application/problem+json",
                cancellationToken: http.RequestAborted));
    }
}
