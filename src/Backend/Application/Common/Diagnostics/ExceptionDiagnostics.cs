using System.Data.Common;
using System.Diagnostics;

namespace Application.Common.Diagnostics;

/// <summary>Diagnostic identifiers without exception messages, parameter values or source-file paths.</summary>
public sealed record ExceptionDiagnostics(string ErrorType, string? DatabaseCode, string Location)
{
    public static ExceptionDiagnostics Capture(Exception exception)
    {
        string? code = null;
        Exception? current = exception;
        for (int depth = 0; current is not null && depth < 8; depth++, current = current.InnerException)
        {
            if (current is DbException database && database.SqlState is { Length: 5 } state
                && state.All(char.IsAsciiLetterOrDigit))
            {
                code = state;
                break;
            }
        }

        var frames = new StackTrace(exception, false).GetFrames();
        string location = string.Join(" <- ", frames.Take(12).Select(frame => frame.GetMethod())
            .Where(method => method is not null)
            .Select(method => $"{method?.DeclaringType?.FullName}.{method?.Name}"));
        return new ExceptionDiagnostics(exception.GetType().FullName ?? exception.GetType().Name,
            code, location.Length == 0 ? "unavailable" : location);
    }
}
