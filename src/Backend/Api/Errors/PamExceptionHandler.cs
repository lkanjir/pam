using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace Api.Errors;

public sealed class PamExceptionHandler(
    IProblemDetailsService problemDetails,
    ILogger<PamExceptionHandler> logger) : IExceptionHandler
{
    private const string RequestFailedMessage =
        "Request failed. Status: {StatusCode}, error type: {ErrorType}, correlation: {CorrelationId}";

    private static readonly Action<ILogger, int, string?, string, Exception?> LogServerFailure =
        LoggerMessage.Define<int, string?, string>(LogLevel.Error, new EventId(0), RequestFailedMessage);

    private static readonly Action<ILogger, int, string?, string, Exception?> LogClientFailure =
        LoggerMessage.Define<int, string?, string>(LogLevel.Information, new EventId(0), RequestFailedMessage);

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

        var logFailure = status >= 500 ? LogServerFailure : LogClientFailure;
        logFailure(
            logger,
            status,
            exception.GetType().FullName,
            httpContext.TraceIdentifier,
            null);

        await problemDetails.WriteAsync(
            new ProblemDetailsContext
            {
                HttpContext = httpContext,
                ProblemDetails = new ProblemDetails { Status = status }
            });

        return true;
    }
}
