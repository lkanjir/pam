using System.Data.Common;
using System.Globalization;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Infrastructure.Sessions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Backend.IntegrationTests.Sessions;

[Collection("Cookie sessions")]
public sealed class OrphanSessionLeaseTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(1799, false)]
    [InlineData(1800, true)]
    [InlineData(1801, true)]
    public async Task Run_UnpublishedMissingTicket_DiscardsLeaseOnlyAtOrAfterExpiryWithoutInventingAudit(int seconds, bool removed)
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        string id = await test.StoreAsync();
        string hash = SessionIdentifier.Hash(id);
        await test.Tickets.RemoveAsync(id);
        test.Clock.Now = test.Clock.Now.AddSeconds(seconds);

        // Act
        await test.RunAsync();

        // Assert
        var observed = await test.Tickets.ObserveAsync(hash);
        Assert.False(observed.HasTicket);
        Assert.Equal(removed, observed.LeaseExpiresAt is null);
        Assert.Null(observed.PendingEnd);
        Assert.False(await test.Database.Context.AuthenticationSessionLedgers.AnyAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync());
    }

    [Fact]
    public async Task Run_UnpublishedLiveTicket_PreservesTicketAndRecoveryLease()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        string id = await test.StoreAsync();
        var before = await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id));

        // Act
        await test.RunAsync();

        // Assert
        var after = await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id));
        Assert.True(after.HasTicket);
        Assert.Equal(before.LeaseVersion, after.LeaseVersion);
        Assert.NotNull(await test.Tickets.RetrieveAsync(id));
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync());
    }

    [Fact]
    public async Task Run_PublishedExpiredSession_PreservesKnownDeadlineForExactEndAudit()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        string id = await test.StoreAsync();
        var session = await test.StartedAsync(id);
        await new SessionLedgerWriter(test.Database.Context, test.Clock).RecordStartedAsync(session);
        await test.Tickets.RemoveAsync(id);
        test.Clock.Now = test.Clock.Now.AddMinutes(31);

        // Act
        await test.RunAsync();

        // Assert
        var ledger = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal("expired", ledger.EndReason);
        Assert.Equal(session.ExpectedExpiresAt.UtcDateTime, ledger.EndedAt);
        var audit = await test.Database.Context.AuditEvents.SingleAsync(value => value.EventType == "authentication.session.ended");
        Assert.Equal(session.ExpectedExpiresAt.UtcDateTime, audit.OccurredAt);
        Assert.Equal("expired", audit.ReasonCode);
        Assert.Null((await test.Tickets.ObserveAsync(session.SessionIdHash)).LeaseExpiresAt);
    }

    [Fact]
    public async Task Run_CleanupCommitsBeforeDelayedPublication_ExpiredStartCannotAppearLater()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        string id = await test.StoreAsync();
        var session = await test.StartedAsync(id);
        await test.Tickets.RemoveAsync(id);
        test.Clock.Now = session.ExpectedExpiresAt;

        // Act
        await test.RunAsync();
        var writer = new SessionLedgerWriter(test.Database.Context, test.Clock);

        // Assert
        Assert.Null((await test.Tickets.ObserveAsync(session.SessionIdHash)).LeaseExpiresAt);
        await Assert.ThrowsAsync<InvalidOperationException>(() => writer.RecordStartedAsync(session));
        Assert.False(await test.Database.Context.AuthenticationSessionLedgers.AnyAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync());
    }

    [Fact]
    public async Task Run_PublicationHasUncommittedLedger_WaitsBeforeClassifyingLeaseAsOrphan()
    {
        // Arrange
        var publication = new PublicationCommitGate();
        await using var test = await LeaseContext.CreateAsync(postgres, redis, publication);
        string id = await test.StoreAsync();
        var session = await test.StartedAsync(id);
        publication.Armed = true;
        var writer = new SessionLedgerWriter(test.Database.Context, test.Clock);
        var started = writer.RecordStartedAsync(session);
        await publication.Entered.Task.WaitAsync(TimeSpan.FromSeconds(20));
        await test.Tickets.RemoveAsync(id);
        test.Clock.Now = session.ExpectedExpiresAt;
        var cleanupLock = new CleanupLockObserver();

        // Act
        var cleanup = test.RunAsync(observer: cleanupLock);
        await cleanupLock.Entered.Task.WaitAsync(TimeSpan.FromSeconds(20));
        publication.Release.TrySetResult();
        await Task.WhenAll(started, cleanup).WaitAsync(TimeSpan.FromSeconds(20));

        // Assert
        var ledger = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal("expired", ledger.EndReason);
        Assert.Equal(session.ExpectedExpiresAt.UtcDateTime, ledger.EndedAt);
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "authentication.session.started"));
        Assert.Equal(1, await test.Database.Context.AuditEvents.CountAsync(value => value.EventType == "authentication.session.ended" && value.ReasonCode == "expired"));
    }

    [Fact]
    public async Task ReadLeasePage_MultipleBoundedPasses_ResumesAcrossPageOffsetsWithoutStarvation()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        var expected = new HashSet<string>(StringComparer.Ordinal);
        for (int index = 0; index < 513; index++)
        {
            expected.Add(SessionIdentifier.Hash(await test.StoreAsync()));
        }
        var position = new SessionLeasePosition();
        var actual = new HashSet<string>(StringComparer.Ordinal);
        bool wrapped = false;
        bool resumedServerCursor = false;

        // Act
        for (int pass = 0; pass < 50; pass++)
        {
            var page = await test.Tickets.ReadLeasePageAsync(position, 17);
            Assert.InRange(page.SessionIdHashes.Count, 0, 17);
            actual.UnionWith(page.SessionIdHashes);
            position = page.Next;
            resumedServerCursor |= position.Cursor != 0;
            if (position == new SessionLeasePosition())
            {
                wrapped = true;
                break;
            }
        }

        // Assert
        Assert.True(wrapped);
        Assert.True(resumedServerCursor);
        Assert.True(expected.SetEquals(actual));
    }

    [Fact]
    public async Task Run_LeaseCursorWithNoLedgerRows_ProgressesAndEventuallyClearsAllExpiredOrphans()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        var hashes = new List<string>();
        for (int index = 0; index < 11; index++)
        {
            string id = await test.StoreAsync();
            hashes.Add(SessionIdentifier.Hash(id));
            await test.Tickets.RemoveAsync(id);
        }
        test.Clock.Now = test.Clock.Now.AddMinutes(30);
        var position = new SessionReconciliationPosition();

        // Act
        for (int pass = 0; pass < 40; pass++)
        {
            position = await test.RunAsync(position, 2);
        }

        // Assert
        foreach (string hash in hashes)
        {
            Assert.Null((await test.Tickets.ObserveAsync(hash)).LeaseExpiresAt);
        }
        Assert.False(await test.Database.Context.AuthenticationSessionLedgers.AnyAsync());
        Assert.False(await test.Database.Context.AuditEvents.AnyAsync());
    }

    [Fact]
    public async Task DiscardExpiredLease_RenewalChangesObservedLease_DoesNotDeleteCurrentRecoveryState()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        string id = await test.StoreAsync();
        string hash = SessionIdentifier.Hash(id);
        var old = await test.Tickets.ObserveAsync(hash);
        test.Clock.Now = test.Clock.Now.AddMinutes(20);
        Assert.True(await test.Tickets.TryRenewAsync(id, SessionTestData.Ticket(test.Clock.Now)));
        await test.Tickets.RemoveAsync(id);
        test.Clock.Now = test.Clock.Now.AddMinutes(10);
        var current = await test.Tickets.ObserveAsync(hash);

        // Act
        bool discarded = await test.Tickets.DiscardExpiredLeaseAsync(hash, old with { HasTicket = false });

        // Assert
        Assert.False(discarded);
        Assert.NotEqual(old.LeaseVersion, current.LeaseVersion);
        Assert.Equal(current.LeaseVersion, (await test.Tickets.ObserveAsync(hash)).LeaseVersion);
    }

    [Fact]
    public async Task DiscardExpiredLease_AnEndIntentWinsAfterObservation_PreservesItsOriginalReasonAndTime()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        string id = await test.StoreAsync();
        string hash = SessionIdentifier.Hash(id);
        await test.Tickets.RemoveAsync(id);
        test.Clock.Now = test.Clock.Now.AddMinutes(30);
        var old = await test.Tickets.ObserveAsync(hash);
        var end = new PendingSessionEnd(hash, test.Clock.Now, "logout", "original");
        Assert.NotNull(await test.Tickets.EndAsync(end));

        // Act
        bool discarded = await test.Tickets.DiscardExpiredLeaseAsync(hash, old);

        // Assert
        Assert.False(discarded);
        var pending = (await test.Tickets.ObserveAsync(hash)).PendingEnd;
        Assert.NotNull(pending);
        Assert.Equal("logout", pending.Reason);
        Assert.Equal(end.EndedAt, pending.EndedAt);
        Assert.Equal("original", pending.CorrelationId);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1001)]
    public async Task ReadLeasePage_InvalidLimit_IsRejected(int limit)
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);

        // Act / Assert
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => test.Tickets.ReadLeasePageAsync(new(), limit));
    }

    [Fact]
    public async Task ReadLeasePage_PreCancelled_IsRejectedBeforeEnumeration()
    {
        // Arrange
        await using var test = await LeaseContext.CreateAsync(postgres, redis);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // Act / Assert
        await Assert.ThrowsAsync<OperationCanceledException>(() => test.Tickets.ReadLeasePageAsync(new(), 10, cancellation.Token));
    }

    private sealed class PublicationCommitGate : DbTransactionInterceptor
    {
        public bool Armed { get; set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override async ValueTask<InterceptionResult> TransactionCommittingAsync(DbTransaction transaction,
            TransactionEventData eventData, InterceptionResult result, CancellationToken cancellationToken = default)
        {
            if (Armed)
            {
                Entered.TrySetResult();
                await Release.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
            }
            return result;
        }
    }

    private sealed class CleanupLockObserver : DbCommandInterceptor
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("pg_advisory_xact_lock", StringComparison.Ordinal))
            {
                Entered.TrySetResult();
            }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class LeaseContext(TestDatabase database, ServiceProvider services, TestTimeProvider clock, long principalId) : IAsyncDisposable
    {
        public TestDatabase Database => database;
        public TestTimeProvider Clock => clock;
        public ISessionTicketStore Tickets => services.GetRequiredService<ISessionTicketStore>();

        public static async Task<LeaseContext> CreateAsync(PostgresFixture postgres, RedisFixture redis, params IInterceptor[] interceptors)
        {
            var database = await postgres.CreateDatabaseAsync(interceptors);
            var clock = new TestTimeProvider();
            string id = await SessionTestHost.SeedPrincipalAsync(database);
            return new(database, SessionTestHost.CreateServices(database, clock, redis.Connection), clock,
                long.Parse(id, CultureInfo.InvariantCulture));
        }

        public Task<string> StoreAsync() => Tickets.StoreAsync(SessionTestData.Ticket(clock.Now, principalId.ToString(CultureInfo.InvariantCulture)));

        public async Task<SessionStarted> StartedAsync(string id)
        {
            var principal = await database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == principalId);
            return new(new PrincipalSnapshot(principal.Id, principal.PublicId, principal.DisplayName, principal.Issuer, principal.Subject),
                SessionIdentifier.Hash(id), null, clock.Now, clock.Now.AddMinutes(30), new SessionRequestMetadata(null, null, "publication"));
        }

        public async Task<SessionReconciliationPosition> RunAsync(SessionReconciliationPosition? position = null,
            int limit = 100, IInterceptor? observer = null)
        {
            var options = new DbContextOptionsBuilder<PamDbContext>()
                .UseNpgsql(database.Context.Database.GetConnectionString()).UseSnakeCaseNamingConvention();
            if (observer is not null)
            {
                options.AddInterceptors(observer);
            }
            await using var context = new PamDbContext(options.Options);
            var reconciler = new SessionReconciler(context, Tickets, new SessionLedgerWriter(context, clock), clock,
                NullLogger<SessionReconciler>.Instance);
            return await reconciler.RunAsync(position ?? new(), limit);
        }

        public async ValueTask DisposeAsync()
        {
            await services.DisposeAsync();
            await database.DisposeAsync();
        }
    }
}
