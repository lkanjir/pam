using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Api.Errors;

public sealed class PamExceptionHandler(
    IProblemDetailsService problemDetails,
    ILogger<PamExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(
        HttpContext httpContext,
        Exception exception,
        CancellationToken cancellationToken)
    {
        if (httpContext.RequestAborted.IsCancellationRequested)
        {
            return true;
        }

        int status = exception is BadHttpRequestException badRequest
            ? badRequest.StatusCode
            : StatusCodes.Status500InternalServerError;

        logger.Log(
            status >= 500 ? LogLevel.Error : LogLevel.Information,
            "Request failed. Status: {StatusCode}, error type: {ErrorType}, correlation: {CorrelationId}",
            status,
            exception.GetType().FullName,
            httpContext.TraceIdentifier);

        await problemDetails.WriteAsync(
            new ProblemDetailsContext
            {
                HttpContext = httpContext, ProblemDetails = new ProblemDetails { Status = status }
            });

        return true;
    }
}
