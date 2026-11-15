using Api.Errors;
using Application.Common.Diagnostics;
using FakeItEasy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Backend.UnitTests.Errors;

public sealed class ExceptionDiagnosticsTests
{
    [Fact]
    public async Task Handle_ThrownDatabaseFailure_LogsLocationAndCodeWithoutExceptionValues()
    {
        // Arrange
        var logger = A.Fake<ILogger<PamExceptionHandler>>();
        A.CallTo(() => logger.IsEnabled(A<LogLevel>._)).Returns(true);
        var problems = A.Fake<IProblemDetailsService>();
        var handler = new PamExceptionHandler(problems, logger);
        var context = new DefaultHttpContext { TraceIdentifier = "diagnostic-request" };
        var error = CaptureFailure("23505");

        // Act
        bool handled = await handler.TryHandleAsync(context, error, CancellationToken.None);

        // Assert
        Assert.True(handled);
        var call = Assert.Single(Fake.GetCalls(logger), item => item.Method.Name == "Log");
        Assert.Null(call.Arguments[3]);
        var state = Assert.IsAssignableFrom<IReadOnlyList<KeyValuePair<string, object?>>>(call.Arguments[2]);
        var fields = state.ToDictionary(item => item.Key, item => item.Value);
        Assert.Equal("23505", fields["DatabaseCode"]);
        Assert.Equal("System.InvalidOperationException", fields["ErrorType"]);
        Assert.Equal("diagnostic-request", fields["CorrelationId"]);
        var location = Assert.IsType<string>(fields["ErrorLocation"]);
        Assert.Contains(nameof(CaptureFailure), location, StringComparison.Ordinal);
        Assert.DoesNotContain("credential-sentinel", call.Arguments[2]?.ToString(), StringComparison.Ordinal);
        A.CallTo(() => problems.WriteAsync(A<ProblemDetailsContext>.That.Matches(
            problem => problem.ProblemDetails.Status == 500 && problem.ProblemDetails.Detail == null)))
            .MustHaveHappenedOnceExactly();
    }

    [Fact]
    public void Capture_UnthrownException_ReportsUnavailableLocationWithoutMessage()
    {
        // Arrange
        var exception = new InvalidOperationException("credential-sentinel");

        // Act
        var result = ExceptionDiagnostics.Capture(exception);

        // Assert
        Assert.Equal(new ExceptionDiagnostics("System.InvalidOperationException", null, "unavailable"), result);
    }

    [Fact]
    public void Capture_UnexpectedProviderCode_DoesNotCopyArbitraryText()
    {
        // Arrange
        var exception = CaptureFailure("credential-sentinel");

        // Act
        var result = ExceptionDiagnostics.Capture(exception);

        // Assert
        Assert.Null(result.DatabaseCode);
        Assert.Contains(nameof(CaptureFailure), result.Location, StringComparison.Ordinal);
        Assert.DoesNotContain("credential-sentinel", result.ToString(), StringComparison.Ordinal);
    }

    private static InvalidOperationException CaptureFailure(string code)
    {
        try
        {
            throw new InvalidOperationException("credential-sentinel",
                new PostgresException("credential-sentinel", "ERROR", "ERROR", code));
        }
        catch (InvalidOperationException exception)
        {
            return exception;
        }
    }
}
