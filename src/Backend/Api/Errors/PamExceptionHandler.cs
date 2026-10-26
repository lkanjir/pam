using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Api.Errors;

public sealed class PamExceptionHandler(
    IProblemDetailsService problemDetails,
    ILogger<PamExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        // Log metadata only: exception messages can contain credentials or SQL data.
        logger.LogError("Unhandled request failure. Error type: {ErrorType}; correlation: {CorrelationId}.",
            exception.GetType().FullName, httpContext.TraceIdentifier);

        await problemDetails.WriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = new ProblemDetails
            {
                Status = StatusCodes.Status500InternalServerError,
                Title = "An unexpected error occurred."
            }
        });
        return true;
    }
}
