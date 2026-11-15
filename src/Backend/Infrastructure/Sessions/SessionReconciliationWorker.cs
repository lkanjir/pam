using Application.Common.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Infrastructure.Sessions;

public sealed class SessionReconciliationWorker(
    IServiceScopeFactory scopeFactory,
    IOptions<SessionReconciliationOptions> options,
    TimeProvider timeProvider,
    ILogger<SessionReconciliationWorker> logger) : BackgroundService
{
    private static readonly Action<ILogger, string, string?, string, Exception?> LogPassFailure =
        LoggerMessage.Define<string, string?, string>(LogLevel.Error, new EventId(0),
            "Session reconciliation pass failed; it will retry on the next interval. " +
            "Error type: {ErrorType}; database code: {DatabaseCode}; location: {ErrorLocation}.");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var settings = options.Value;
        if (!settings.Enabled)
        {
            return;
        }

        var position = new SessionReconciliationPosition();
        using var timer = new PeriodicTimer(settings.Interval, timeProvider);
        try
        {
            do
            {
                try
                {
                    await using var scope = scopeFactory.CreateAsyncScope();
                    position = await scope.ServiceProvider.GetRequiredService<SessionReconciler>()
                        .RunAsync(position, settings.BatchSize, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception exception)
                {
                    var diagnostic = ExceptionDiagnostics.Capture(exception);
                    LogPassFailure(logger, diagnostic.ErrorType, diagnostic.DatabaseCode, diagnostic.Location, null);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown, including cancellation while waiting for the next pass.
        }
    }
}
