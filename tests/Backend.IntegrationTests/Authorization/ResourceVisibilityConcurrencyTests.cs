using System.Data.Common;
using Application.AccessRequests;
using Application.Principals;
using Application.Resources;
using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Resources;
using Backend.IntegrationTests.Sessions;
using FakeItEasy;
using Infrastructure.AccessRequests;
using Infrastructure.Authentication;
using Infrastructure.Persistence;
using Infrastructure.Persistence.Entities;
using Infrastructure.Principals;
using Infrastructure.Resources;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using static Backend.IntegrationTests.AccessRequests.AccessRequestTestData;

namespace Backend.IntegrationTests.Authorization;

[Collection("Cookie sessions")]
public sealed class ResourceVisibilityConcurrencyTests(PostgresFixture postgres, RedisFixture redis)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Submit_ConcurrentSupportingRoleRemoval_RespectsPrincipalLockOrder(bool removalFirst)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var entitlement = await SeedEntitlementAsync(test);
        var admin = await AddAdminAsync(test);
        var requester = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var gate = new AuditGate(removalFirst ? "role.removed" : "access_request.created");
        var attempt = new CommandAttempt(removalFirst ? "FROM principals" : "FROM pam_roles", "FOR UPDATE");
        await using var submissionContext = Context(test, removalFirst ? attempt : gate);
        await using var removalContext = Context(test, removalFirst ? gate : attempt);
        var requests = new AccessRequestService(submissionContext, test.Clock);
        var roles = new PrincipalRoleService(removalContext, test.Clock, A.Fake<ISessionTicketStore>());
        Task<AccessRequestSubmissionResult> submission;
        Task<PrincipalRoleWriteResult> removal;

        // Act
        if (removalFirst)
        {
            removal = roles.RemoveAsync(requester.PublicId, "user", new() { Reason = "Revoke requester" },
                new(Snapshot(admin), test.Clock.Now), requester.Version, "remove-first");
            await gate.Ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
            submission = requests.SubmitAsync(Request(test, entitlement), "pending-request", Snapshot(requester), "submit-second");
        }
        else
        {
            submission = requests.SubmitAsync(Request(test, entitlement), "pending-request", Snapshot(requester), "submit-first");
            await gate.Ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
            removal = roles.RemoveAsync(requester.PublicId, "user", new() { Reason = "Revoke requester" },
                new(Snapshot(admin), test.Clock.Now), requester.Version, "remove-second");
        }
        try
        {
            await attempt.Started.Task.WaitAsync(TimeSpan.FromSeconds(20));
        }
        finally
        {
            gate.Release.TrySetResult();
        }
        var submitted = await submission;
        var removed = await removal;

        // Assert
        Assert.Equal(PrincipalWriteKind.Succeeded, removed.Kind);
        Assert.Equal(removalFirst ? AccessRequestSubmissionKind.Forbidden : AccessRequestSubmissionKind.Created, submitted.Kind);
        Assert.Equal(removalFirst ? 0 : 1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(removalFirst ? 0 : 1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.False(await test.Database.Context.ResourcePrincipalBindings.AnyAsync(value => value.PrincipalId == requester.Id && value.IsActive));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Submit_ConcurrentResourceRetirement_RespectsSharedResourceLock(bool retirementFirst)
    {
        // Arrange
        await using var test = await ResourceTestContext.CreateAsync(postgres, redis.Connection);
        var entitlement = await SeedEntitlementAsync(test);
        var admin = await AddAdminAsync(test);
        var requester = await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == test.ActorId);
        var gate = new AuditGate(retirementFirst ? "resource.deleted" : "access_request.created", afterSave: retirementFirst);
        var attempt = retirementFirst
            ? new CommandAttempt("FROM managed_resources", "FOR SHARE")
            : new CommandAttempt("UPDATE managed_resources", "");
        await using var submissionContext = Context(test, retirementFirst ? attempt : gate);
        await using var retirementContext = Context(test, retirementFirst ? gate : attempt);
        var requests = new AccessRequestService(submissionContext, test.Clock);
        var resources = new ResourceService(retirementContext, test.Clock);
        Task<AccessRequestSubmissionResult> submission;
        Task<ResourceWriteKind> retirement;

        // Act
        if (retirementFirst)
        {
            retirement = resources.DeleteAsync(test.Resource.PublicId, new(Snapshot(admin), test.Clock.Now), "retire-first", test.Resource.Version);
            await gate.Ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
            submission = requests.SubmitAsync(Request(test, entitlement), "pending-request", Snapshot(requester), "submit-second");
        }
        else
        {
            submission = requests.SubmitAsync(Request(test, entitlement), "pending-request", Snapshot(requester), "submit-first");
            await gate.Ready.Task.WaitAsync(TimeSpan.FromSeconds(20));
            retirement = resources.DeleteAsync(test.Resource.PublicId, new(Snapshot(admin), test.Clock.Now), "retire-second", test.Resource.Version);
        }
        try
        {
            await attempt.Started.Task.WaitAsync(TimeSpan.FromSeconds(20));
        }
        finally
        {
            gate.Release.TrySetResult();
        }
        var submitted = await submission;
        var retired = await retirement;

        // Assert
        Assert.Equal(ResourceWriteKind.Succeeded, retired);
        Assert.Equal(retirementFirst ? AccessRequestSubmissionKind.NotFound : AccessRequestSubmissionKind.Created, submitted.Kind);
        Assert.Equal(retirementFirst ? 0 : 1, await test.Database.Context.AccessRequests.CountAsync());
        Assert.Equal(retirementFirst ? 0 : 1, await test.Database.Context.PolicyEvaluations.CountAsync());
        Assert.False(await test.Database.Context.ManagedResources.AnyAsync(value => value.Id == test.Resource.Id));
    }

    private static async Task<Principal> AddAdminAsync(ResourceTestContext test)
    {
        var admin = Principal.CreateMapping("https://identity.example/realms/pam", "second-admin", "Second Admin", test.Clock.Now);
        test.Database.Context.Principals.Add(admin);
        await test.Database.Context.SaveChangesAsync();
        await test.Database.Context.Principals.Where(value => value.Id == admin.Id)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, true));
        await SessionTestHost.AssignRolesAsync(test.Database, admin.Id, "admin");
        return await test.Database.Context.Principals.AsNoTracking().SingleAsync(value => value.Id == admin.Id);
    }

    private static PrincipalSnapshot Snapshot(Principal principal) => new(principal.Id, principal.PublicId,
        principal.DisplayName, principal.Issuer, principal.Subject);

    private static PamDbContext Context(ResourceTestContext test, IInterceptor interceptor) => new(
        new DbContextOptionsBuilder<PamDbContext>().UseNpgsql(test.Database.Context.Database.GetConnectionString())
            .UseSnakeCaseNamingConvention().AddInterceptors(interceptor).Options);

    private sealed class AuditGate(string eventType, bool afterSave = false) : SaveChangesInterceptor
    {
        public TaskCompletionSource Ready { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        private bool Matches(DbContextEventData eventData) =>
            eventData.Context?.ChangeTracker.Entries<AuditEvent>().Any(entry => entry.Entity.EventType == eventType) == true;

        private async Task PauseAsync(CancellationToken cancellationToken)
        {
            Ready.TrySetResult();
            await Release.Task.WaitAsync(TimeSpan.FromSeconds(20), cancellationToken);
        }

        public override async ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (!afterSave && Matches(eventData))
            {
                await PauseAsync(cancellationToken);
            }
            return result;
        }

        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData,
            int result, CancellationToken cancellationToken = default)
        {
            if (afterSave && Matches(eventData))
            {
                await PauseAsync(cancellationToken);
            }
            return result;
        }
    }

    private sealed class CommandAttempt(string firstFragment, string secondFragment) : DbCommandInterceptor
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains(firstFragment, StringComparison.Ordinal)
                && command.CommandText.Contains(secondFragment, StringComparison.Ordinal))
            {
                Started.TrySetResult();
            }
            return ValueTask.FromResult(result);
        }
    }
}
