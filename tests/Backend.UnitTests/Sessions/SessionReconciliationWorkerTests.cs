using System.Threading.Channels;
using Infrastructure;
using Infrastructure.Sessions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Backend.UnitTests.Sessions;

public sealed class SessionReconciliationWorkerTests
{
    [Theory]
    [InlineData("00:00:00", "200")]
    [InlineData("01:00:01", "200")]
    [InlineData("00:00:30", "0")]
    [InlineData("00:00:30", "1001")]
    public void Options_InvalidBounds_FailValidation(string interval, string batchSize)
    {
        // Arrange
        using var services = CreateServices(interval, batchSize);

        // Act / Assert
        Assert.Throws<OptionsValidationException>(() =>
            services.GetRequiredService<IOptions<SessionReconciliationOptions>>().Value);
    }

    [Theory]
    [InlineData("00:00:01", "1")]
    [InlineData("01:00:00", "1000")]
    public void Options_ValidBounds_ArePreserved(string interval, string batchSize)
    {
        // Arrange
        using var services = CreateServices(interval, batchSize);

        // Act
        var options = services.GetRequiredService<IOptions<SessionReconciliationOptions>>().Value;

        // Assert
        Assert.Equal(TimeSpan.Parse(interval, System.Globalization.CultureInfo.InvariantCulture), options.Interval);
        Assert.Equal(int.Parse(batchSize, System.Globalization.CultureInfo.InvariantCulture), options.BatchSize);
        Assert.True(options.Enabled);
    }

    [Fact]
    public async Task Worker_Disabled_DoesNotCreateScopeOrTimer()
    {
        // Arrange
        var scopes = new FailingScopeFactory();
        var clock = new ManualTimerProvider();
        using var worker = new SessionReconciliationWorker(scopes,
            Options.Create(new SessionReconciliationOptions { Enabled = false }), clock, new PassLogger());

        // Act
        await worker.StartAsync(CancellationToken.None);
        Assert.NotNull(worker.ExecuteTask);
        await worker.ExecuteTask.WaitAsync(TimeSpan.FromSeconds(10));

        // Assert
        Assert.Equal(0, scopes.Calls);
        Assert.Null(clock.Timer);
    }

    [Fact]
    public async Task Worker_FailedPass_RetriesOnlyOnTickAndStopsCleanly()
    {
        // Arrange
        var scopes = new FailingScopeFactory();
        var clock = new ManualTimerProvider();
        var logger = new PassLogger();
        using var worker = new SessionReconciliationWorker(scopes,
            Options.Create(new SessionReconciliationOptions()), clock, logger);

        // Act
        await worker.StartAsync(CancellationToken.None);
        string first = await logger.Passes.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(1, scopes.Calls);
        var timer = clock.Timer;
        Assert.NotNull(timer);
        timer.Fire();
        await logger.Passes.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await worker.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(10));
        timer.Fire();

        // Assert
        Assert.Equal(2, scopes.Calls);
        Assert.True(timer.Disposed);
        Assert.Contains(nameof(InvalidOperationException), first, StringComparison.Ordinal);
        Assert.Contains(nameof(FailingScopeFactory.CreateScope), first, StringComparison.Ordinal);
        Assert.DoesNotContain("private-exception-message", first, StringComparison.Ordinal);
        Assert.False(logger.Passes.Reader.TryRead(out _));
    }

    private static ServiceProvider CreateServices(string interval, string batchSize)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SessionReconciliation:Interval"] = interval,
            ["SessionReconciliation:BatchSize"] = batchSize
        }).Build();
        return new ServiceCollection().AddInfrastructure(configuration).BuildServiceProvider();
    }

    private sealed class FailingScopeFactory : IServiceScopeFactory
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public IServiceScope CreateScope()
        {
            Interlocked.Increment(ref _calls);
            throw new InvalidOperationException("private-exception-message");
        }
    }

    private sealed class PassLogger : ILogger<SessionReconciliationWorker>
    {
        public Channel<string> Passes { get; } = Channel.CreateUnbounded<string>();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Assert.Null(exception);
            Passes.Writer.TryWrite(formatter(state, exception));
        }
    }

    private sealed class ManualTimerProvider : TimeProvider
    {
        public ManualTimer? Timer { get; private set; }
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            Timer = new ManualTimer(callback, state);
            return Timer;
        }
    }

    private sealed class ManualTimer(TimerCallback callback, object? state) : ITimer
    {
        public bool Disposed { get; private set; }
        public bool Change(TimeSpan dueTime, TimeSpan period) => !Disposed;
        public void Fire()
        {
            if (!Disposed)
            {
                callback(state);
            }
        }
        public void Dispose() => Disposed = true;
        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
