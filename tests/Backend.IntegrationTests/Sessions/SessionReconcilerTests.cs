using Api.Authentication;
using Application.Identity;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using FakeItEasy;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

namespace Backend.IntegrationTests.Sessions;

[Collection(StorageCollection3.Name)]
public sealed class SessionReconcilerTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Run_DisabledAccount_RevokesOnlyItsSessionsAtKnownOrDetectedTime(bool recordedAudit)
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string first = await test.StartAsync();
        string second = await test.StartAsync();
        long otherPrincipal = await test.AddEnabledPrincipalAsync();
        string unaffected = await test.StartAsync(otherPrincipal);
        var disabledAt = test.Clock.Now.AddMinutes(2);
        await test.DisableAsync(recordedAudit ? disabledAt : null);
        test.Clock.Now = test.Clock.Now.AddMinutes(8);
        var expectedEnd = recordedAudit ? disabledAt : test.Clock.Now;

        // Act
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(first, "access_changed", expectedEnd);
        await test.AssertEndAsync(second, "access_changed", expectedEnd);
        Assert.Null(await test.Tickets.RetrieveAsync(first));
        Assert.Null(await test.Tickets.RetrieveAsync(second));
        Assert.NotNull(await test.Tickets.RetrieveAsync(unaffected));
        string unaffectedHash = SessionIdentifier.Hash(unaffected);
        Assert.Null(await test.Database.Context.AuthenticationSessionLedgers.Where(session => session.SessionIdHash == unaffectedHash)
            .Select(session => session.EndedAt).SingleAsync());
    }

    [Fact]
    public async Task Run_DisableAuditPredatesLatePublication_DoesNotEndBeforeSessionCreation()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        var createdAt = test.Clock.Now;
        await test.DisableAsync(createdAt.AddSeconds(-1));
        test.Clock.Now = test.Clock.Now.AddMinutes(1);

        // Act
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(id, "access_changed", createdAt);
        Assert.Null(await test.Tickets.RetrieveAsync(id));
    }

    [Fact]
    public async Task Run_DisabledAccountWithPendingLogout_PreservesFirstCompletion()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        var logoutAt = test.Clock.Now.AddMinutes(1);
        await test.Tickets.EndAsync(new PendingSessionEnd(SessionIdentifier.Hash(id), logoutAt, "logout", "original-logout"));
        await test.DisableAsync(test.Clock.Now.AddMinutes(2));
        test.Clock.Now = test.Clock.Now.AddMinutes(3);

        // Act
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(id, "logout", logoutAt);
    }

    [Fact]
    public async Task Run_DisabledAccountEndAuditRejected_RetainsRevocationAndOriginalTimeForRetry()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        var disabledAt = test.Clock.Now.AddMinutes(2);
        await test.DisableAsync(disabledAt);
        test.Clock.Now = test.Clock.Now.AddMinutes(3);
        await SessionTestHost.RejectLogoutAuditAsync(test.Database);
        await test.RunAsync();
        Assert.Null(await test.Tickets.RetrieveAsync(id));
        var pending = (await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id))).PendingEnd;
        Assert.NotNull(pending);
        Assert.Equal("access_changed", pending.Reason);
        Assert.Equal(disabledAt, pending.EndedAt);
        Assert.Null(await test.Database.Context.AuthenticationSessionLedgers.Select(session => session.EndedAt).SingleAsync());
        await test.Database.Context.Database.ExecuteSqlRawAsync("ALTER TABLE audit_events DROP CONSTRAINT reject_session_end");
        test.Clock.Now = test.Clock.Now.AddMinutes(5);

        // Act
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(id, "access_changed", disabledAt);
        Assert.Null((await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id))).PendingEnd);
    }

    [Fact]
    public async Task Run_LiveRenewalWithStaleLedger_RepairsExpiryWithoutEndingSession()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        var initial = test.Clock.Now;
        test.Clock.Now = initial.AddMinutes(16);
        var ticket = await test.Tickets.RetrieveAsync(id);
        Assert.NotNull(ticket);
        ticket.Properties.ExpiresUtc = initial.AddMinutes(46);
        Assert.True(await test.Tickets.TryRenewAsync(id, ticket));

        // Act
        await test.RunAsync();

        // Assert
        var row = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal(initial.AddMinutes(46).UtcDateTime, row.ExpectedExpiresAt);
        Assert.Null(row.EndedAt);
        Assert.Empty(await test.Database.Context.AuditEvents.Where(e => e.EventType == "authentication.session.ended").ToListAsync());
        Assert.NotNull(await test.Tickets.RetrieveAsync(id));
    }

    [Fact]
    public async Task Renew_DatabaseRejectsExpiry_LeavesTicketValidForLaterReconciliation()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        var initial = test.Clock.Now;
        await test.Database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE authentication_session_ledger ADD CONSTRAINT reject_renewal CHECK (expected_expires_at <= TIMESTAMPTZ '2026-10-23 12:30:00Z')");
        test.Clock.Now = initial.AddMinutes(16);
        var ticket = await test.Tickets.RetrieveAsync(id);
        Assert.NotNull(ticket);
        ticket.Properties.ExpiresUtc = initial.AddMinutes(46);

        // Act
        await test.Services.GetRequiredService<ITicketStore>().RenewAsync(id, ticket);

        // Assert
        Assert.Equal(initial.AddMinutes(46), (await test.Tickets.RetrieveAsync(id))?.Properties.ExpiresUtc);
        Assert.Equal(initial.AddMinutes(30).UtcDateTime,
            await test.Database.Context.AuthenticationSessionLedgers.Select(s => s.ExpectedExpiresAt).SingleAsync());
        await test.Database.Context.Database.ExecuteSqlRawAsync("ALTER TABLE authentication_session_ledger DROP CONSTRAINT reject_renewal");
        await test.RunAsync();
        var row = await test.Database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync();
        Assert.Equal(initial.AddMinutes(46).UtcDateTime, row.ExpectedExpiresAt);
        Assert.Null(row.EndedAt);
    }

    [Theory]
    [InlineData(false, 0)]
    [InlineData(false, 1)]
    [InlineData(true, 1)]
    public async Task Run_KnownExpiry_RecordsDeadlineEvenAfterPhysicalTicketLoss(bool ticketLost, int delayMinutes)
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        var deadline = test.Clock.Now.AddMinutes(30);
        if (ticketLost)
        {
            await test.Tickets.RemoveAsync(id);
        }
        test.Clock.Now = deadline.AddMinutes(delayMinutes);

        // Act
        await test.RunAsync();
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(id, "expired", deadline);
        Assert.Null(await test.Tickets.RetrieveAsync(id));
        Assert.Null((await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id))).PendingEnd);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(40)]
    public async Task Run_AllRedisMetadataLost_RecordsLossAtObservationTime(int minutes)
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        await test.Tickets.DiscardUnissuedAsync(id); // Simulate complete ticket/lease loss, not a normal logout.
        test.Clock.Now = test.Clock.Now.AddMinutes(minutes);
        var discovered = test.Clock.Now;

        // Act
        await test.RunAsync();
        test.Clock.Now = test.Clock.Now.AddHours(1);
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(id, "session_lost", discovered);
    }

    [Fact]
    public async Task Run_EndAuditPreviouslyRejected_RetriesOriginalReasonTimeAndCorrelation()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        test.Clock.Now = test.Clock.Now.AddMinutes(1);
        var endedAt = test.Clock.Now;
        await SessionTestHost.RejectLogoutAuditAsync(test.Database);
        await using (var scope = test.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<SessionTerminator>()
                .EndSessionAsync(id, SessionEndReason.Logout, "original-logout");
        }
        Assert.Null(await test.Database.Context.AuthenticationSessionLedgers.Select(s => s.EndedAt).SingleAsync());
        Assert.NotNull((await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id))).PendingEnd);
        Assert.Null(await test.Tickets.RetrieveAsync(id));
        await test.Database.Context.Database.ExecuteSqlRawAsync("ALTER TABLE audit_events DROP CONSTRAINT reject_session_end");
        test.Clock.Now = test.Clock.Now.AddHours(1);

        // Act
        await Task.WhenAll(test.RunAsync(), test.RunAsync()); // Separate scopes model two API replicas.

        // Assert
        await test.AssertEndAsync(id, "logout", endedAt);
        var audit = await test.Database.Context.AuditEvents.AsNoTracking().SingleAsync(e => e.EventType == "authentication.session.ended");
        Assert.Equal("original-logout", audit.CorrelationId);
        Assert.Null((await test.Tickets.ObserveAsync(SessionIdentifier.Hash(id))).PendingEnd);
    }

    [Fact]
    public async Task Run_FixedCeilingPagination_ReachesOldLostSessionsDespiteNewLogins()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        await test.StartAsync();
        string lost = await test.StartAsync();
        await test.StartAsync();
        await test.Tickets.DiscardUnissuedAsync(lost);
        var position = await test.RunAsync(limit: 1);
        Assert.True(position.AfterId > 0);
        await test.StartAsync();
        await test.StartAsync();

        // Act
        var next = await test.RunAsync(position, 1);
        var wrapped = await test.RunAsync(next, 1);

        // Assert
        Assert.Equal(position.ThroughId, next.ThroughId);
        Assert.True(next.AfterId > position.AfterId);
        Assert.Equal(0, wrapped.AfterId);
        Assert.Equal(0, wrapped.ThroughId);
        await test.AssertEndAsync(lost, "session_lost", test.Clock.Now);
        Assert.Equal(4, await test.Database.Context.AuthenticationSessionLedgers.CountAsync(s => s.EndedAt == null));
    }

    [Fact]
    public async Task Run_AlreadyPersistedCompletion_AcknowledgesWithoutDuplicatingAudit()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        string id = await test.StartAsync();
        string hash = SessionIdentifier.Hash(id);
        await test.Tickets.EndAsync(new PendingSessionEnd(hash, test.Clock.Now, "logout", "first"));
        var writer = new SessionLedgerWriter(test.Database.Context, test.Clock);
        await writer.RecordEndedAsync(hash, test.Clock.Now, "logout", "first");

        // Act
        await test.RunAsync();

        // Assert
        await test.AssertEndAsync(id, "logout", test.Clock.Now);
        Assert.Empty(await test.Tickets.ReadPendingEndsAsync(10));
    }

    [Fact]
    public async Task Run_RedisUnavailable_DoesNotTreatOpenSessionsAsLost()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        await test.StartAsync();
        var tickets = A.Fake<ISessionTicketStore>();
        A.CallTo(() => tickets.ReadPendingEndsAsync(A<int>._, A<CancellationToken>._))
            .Returns(Array.Empty<PendingSessionEnd>());
        A.CallTo(() => tickets.ReadLeasePageAsync(A<SessionLeasePosition>._, A<int>._, A<CancellationToken>._))
            .Returns(new SessionLeasePage(Array.Empty<string>(), new()));
        A.CallTo(() => tickets.ObserveAsync(A<string>._))
            .ThrowsAsync(new StackExchange.Redis.RedisConnectionException(StackExchange.Redis.ConnectionFailureType.UnableToConnect, StackExchange.Redis.CommandFlags.None, "offline"));
        var reconciler = new SessionReconciler(test.Database.Context, tickets,
            new SessionLedgerWriter(test.Database.Context, test.Clock), test.Clock, NullLogger<SessionReconciler>.Instance);

        // Act
        await Assert.ThrowsAsync<StackExchange.Redis.RedisConnectionException>(() => reconciler.RunAsync(new(), 10));

        // Assert
        Assert.Null(await test.Database.Context.AuthenticationSessionLedgers.Select(s => s.EndedAt).SingleAsync());
        Assert.Empty(await test.Database.Context.AuditEvents.Where(e => e.EventType == "authentication.session.ended").ToListAsync());
        A.CallTo(() => tickets.EndAsync(A<PendingSessionEnd>._, A<SessionObservation>._)).MustNotHaveHappened();
    }

    [Fact]
    public async Task Run_PreCancelled_DoesNotReadRecoveryStore()
    {
        // Arrange
        await using var test = await RecoveryContext.CreateAsync(postgres, redis);
        var tickets = A.Fake<ISessionTicketStore>();
        var reconciler = new SessionReconciler(test.Database.Context, tickets,
            new SessionLedgerWriter(test.Database.Context, test.Clock), test.Clock, NullLogger<SessionReconciler>.Instance);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        // Act
        await Assert.ThrowsAsync<OperationCanceledException>(() => reconciler.RunAsync(new(), 10, cancellation.Token));

        // Assert
        A.CallTo(() => tickets.ReadPendingEndsAsync(A<int>._, A<CancellationToken>._)).MustNotHaveHappened();
    }

    private sealed class RecoveryContext(TestDatabase database, ServiceProvider services, TestTimeProvider clock, long principalId) : IAsyncDisposable
    {
        public TestDatabase Database => database;
        public ServiceProvider Services => services;
        public TestTimeProvider Clock => clock;
        public ISessionTicketStore Tickets => services.GetRequiredService<ISessionTicketStore>();

        public static async Task<RecoveryContext> CreateAsync(PostgresFixture postgres, RedisFixture redis)
        {
            var database = await postgres.CreateDatabaseAsync();
            string id = await SessionTestHost.SeedPrincipalAsync(database);
            var clock = new TestTimeProvider();
            var services = SessionTestHost.CreateServices(database, clock, redis.Connection);
            return new(database, services, clock, long.Parse(id, System.Globalization.CultureInfo.InvariantCulture));
        }

        public async Task<string> StartAsync(long? forPrincipalId = null)
        {
            long targetId = forPrincipalId ?? principalId;
            var principal = await database.Context.Principals.SingleAsync(p => p.Id == targetId);
            var identity = PamClaims.Create(new PrincipalIdentity(principal.Id, principal.PublicId,
                principal.DisplayName, true, []), principal.Issuer, principal.Subject, null);
            var ticket = new AuthenticationTicket(identity, new AuthenticationProperties
            {
                IssuedUtc = clock.Now,
                ExpiresUtc = clock.Now.AddMinutes(30)
            }, "Cookies");
            return await services.GetRequiredService<ITicketStore>().StoreAsync(ticket);
        }

        public async Task<long> AddEnabledPrincipalAsync()
        {
            var principal = Principal.CreateMapping("https://identity.example/realms/pam", "bob", "Bob", clock.Now);
            database.Context.Principals.Add(principal);
            await database.Context.SaveChangesAsync();
            await database.Context.Principals.Where(value => value.Id == principal.Id)
                .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
            return principal.Id;
        }

        public async Task DisableAsync(DateTimeOffset? recordedAt)
        {
            await database.Context.Principals.Where(principal => principal.Id == principalId)
                .ExecuteUpdateAsync(update => update.SetProperty(principal => principal.IsEnabled, false));
            if (recordedAt is not { } time)
            {
                return;
            }
            // Include an older event to prove the latest committed disable is selected.
            foreach (var occurredAt in new[] { time.AddMinutes(-10), time })
            {
                database.Context.AuditEvents.Add(new AuditEvent
                {
                    EventType = "principal.disabled",
                    SubjectPrincipalId = principalId,
                    ActorKind = "system",
                    OccurredAt = occurredAt.UtcDateTime,
                    CorrelationId = "reviewed-external-disable",
                    Source = "test.operator",
                    Outcome = "success"
                });
            }
            await database.Context.SaveChangesAsync();
        }

        public async Task<SessionReconciliationPosition> RunAsync(SessionReconciliationPosition? position = null, int limit = 100)
        {
            await using var scope = services.CreateAsyncScope();
            var context = scope.ServiceProvider.GetRequiredService<PamDbContext>();
            var reconciler = new SessionReconciler(context, Tickets, new SessionLedgerWriter(context, clock), clock,
                NullLogger<SessionReconciler>.Instance);
            return await reconciler.RunAsync(position ?? new(), limit);
        }

        public async Task AssertEndAsync(string id, string reason, DateTimeOffset endedAt)
        {
            string hash = SessionIdentifier.Hash(id);
            var row = await database.Context.AuthenticationSessionLedgers.AsNoTracking().SingleAsync(s => s.SessionIdHash == hash);
            Assert.Equal(reason, row.EndReason);
            Assert.Equal(endedAt.UtcDateTime, row.EndedAt);
            var audit = Assert.Single(await database.Context.AuditEvents.AsNoTracking()
                .Where(e => e.EventType == "authentication.session.ended" && e.SessionIdHash == hash).ToListAsync());
            Assert.Equal(reason, audit.ReasonCode);
            Assert.Equal(endedAt.UtcDateTime, audit.OccurredAt);
        }

        public async ValueTask DisposeAsync()
        {
            // Every test owns its database and recovery namespace; remove live test tickets too.
            foreach (string hash in await database.Context.AuthenticationSessionLedgers.Select(s => s.SessionIdHash).ToListAsync())
            {
                await CleanupRedisAsync(hash);
            }
            await services.DisposeAsync();
            await database.DisposeAsync();
        }

        private async Task CleanupRedisAsync(string hash)
        {
            var state = await Tickets.ObserveAsync(hash);
            await Tickets.EndAsync(new PendingSessionEnd(hash, clock.Now, "session_lost", "test-cleanup"), state);
            await Tickets.AcknowledgeEndAsync(hash);
        }
    }
}
