using System.Data.Common;
using Backend.IntegrationTests.Fixtures;
using Infrastructure.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Backend.IntegrationTests.Persistence;

public sealed class EntityRelationshipsTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    private static readonly DateTime CreatedAt = new(2026, 10, 29, 10, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task RoleAssignment_SaveGraph_PreservesAssigneeAndAssigner()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var assignee = CreatePrincipal("ana");
        var assigner = CreatePrincipal("ivan");
        var assignment = new PamRoleAssignment
        {
            Principal = assignee,
            AssignedByPrincipal = assigner,
            Role = new PamRole { Code = "user", CreatedByPrincipal = assigner }
        };
        database.Context.PamRoleAssignments.Add(assignment);

        // Act
        await database.Context.SaveChangesAsync();

        // Assert
        database.Context.ChangeTracker.Clear();
        var saved = await database.Context.PamRoleAssignments
            .Select(a => new
            {
                Assignee = a.Principal.Subject,
                Assigner = a.AssignedByPrincipal.Subject,
                RoleCreator = a.Role.CreatedByPrincipal.Subject
            })
            .SingleAsync();
        Assert.Equal("ana", saved.Assignee);
        Assert.Equal("ivan", saved.Assigner);
        Assert.Equal("ivan", saved.RoleCreator);
    }

    [Fact]
    public async Task Resource_SaveEntitlementGraph_PropagatesGeneratedForeignKey()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var resource = CreateResource(CreatePrincipal("ana"));
        resource.Entitlements.Add(new Entitlement
        {
            Code = "linux.admin",
            Name = "Linux administrator",
            MaxDurationMinutes = 60,
            IsActive = true
        });
        database.Context.ManagedResources.Add(resource);

        // Act
        await database.Context.SaveChangesAsync();

        // Assert
        database.Context.ChangeTracker.Clear();
        long resourceId = await database.Context.Entitlements.Select(e => e.ResourceId).SingleAsync();
        Assert.Equal(resource.Id, resourceId);
    }

    [Fact]
    public async Task Entitlements_ProjectResourceNavigation_UsesSingleDatabaseCommand()
    {
        // Arrange
        var counter = new ReadCommandCounter();
        await using var database = await postgres.CreateDatabaseAsync(counter);
        var resource = CreateResource(CreatePrincipal("ana"));
        var first = CreateEntitlement(resource, "linux.admin");
        var second = CreateEntitlement(resource, "linux.logs");
        database.Context.Entitlements.AddRange(first, second);
        await database.Context.SaveChangesAsync();
        database.Context.ChangeTracker.Clear();
        counter.Reset();

        // Act
        var names = await database.Context.Entitlements
            .AsNoTracking()
            .OrderBy(e => e.Code)
            .Select(e => e.Resource.Name)
            .ToListAsync();

        // Assert
        Assert.Equal(new[] { resource.Name, resource.Name }, names);
        Assert.Equal(1, counter.Count);
        Assert.Empty(database.Context.ChangeTracker.Entries());
    }

    [Fact]
    public async Task Resource_TrackedUpdate_PersistsNewModifierWithoutChangingCreator()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var creator = CreatePrincipal("ana");
        var modifier = CreatePrincipal("ivan");
        var resource = CreateResource(creator);
        database.Context.ManagedResources.Add(resource);
        database.Context.Principals.Add(modifier);
        await database.Context.SaveChangesAsync();
        database.Context.ChangeTracker.Clear();
        var tracked = await database.Context.ManagedResources.SingleAsync();
        tracked.Name = "Updated target";
        tracked.ModifiedAt = CreatedAt.AddHours(1);
        tracked.ModifiedByPrincipalId = modifier.Id;

        // Act
        await database.Context.SaveChangesAsync();

        // Assert
        database.Context.ChangeTracker.Clear();
        var saved = await database.Context.ManagedResources.AsNoTracking().SingleAsync();
        Assert.Equal("Updated target", saved.Name);
        Assert.Equal(CreatedAt.AddHours(1), saved.ModifiedAt);
        Assert.Equal(modifier.Id, saved.ModifiedByPrincipalId);
        Assert.Equal(creator.Id, saved.CreatedByPrincipalId);
        Assert.Equal(CreatedAt, saved.CreatedAt);
    }

    [Fact]
    public async Task Entitlements_HistoryProjection_CanReadSoftDeletedResource()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var resource = CreateResource(CreatePrincipal("ana"));
        resource.DeletedAt = CreatedAt.AddHours(1);
        resource.ModifiedAt = resource.DeletedAt.Value;
        resource.IsActive = false;
        database.Context.Entitlements.Add(CreateEntitlement(resource));
        await database.Context.SaveChangesAsync();
        database.Context.ChangeTracker.Clear();

        // Act
        string name = await database.Context.Entitlements
            .IgnoreQueryFilters()
            .Select(e => e.Resource.Name)
            .SingleAsync();

        // Assert
        Assert.Equal(resource.Name, name);
    }

    [Fact]
    public async Task AuditEvents_IncludeSoftDeletedResource_PreservesHistoricalEvent()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        var resource = CreateResource(CreatePrincipal("ana"));
        resource.DeletedAt = CreatedAt.AddHours(1);
        resource.ModifiedAt = resource.DeletedAt.Value;
        resource.IsActive = false;
        const string snapshot = "{\"name\":\"Linux target\"}";
        database.Context.AuditEvents.Add(new AuditEvent
        {
            EventType = "resource.created",
            ActorKind = "principal",
            Resource = resource,
            ResourceSnapshot = snapshot,
            CorrelationId = "resource-request",
            Source = "pam.api"
        });
        await database.Context.SaveChangesAsync();
        database.Context.ChangeTracker.Clear();

        // Act
        var audit = await database.Context.AuditEvents.AsNoTracking().Include(e => e.Resource).SingleAsync();

        // Assert
        Assert.NotNull(audit.ResourceSnapshot);
        using var json = System.Text.Json.JsonDocument.Parse(audit.ResourceSnapshot);
        Assert.Equal(resource.Name, json.RootElement.GetProperty("name").GetString());
        Assert.Null(audit.Resource);
    }

    private static Principal CreatePrincipal(string subject) => new()
    {
        Issuer = "https://identity.example/realms/pam",
        Subject = subject
    };

    private static ManagedResource CreateResource(Principal actor) => new()
    {
        Name = "Linux target",
        ResourceType = "linux",
        Environment = "dev",
        CreatedAt = CreatedAt,
        ModifiedAt = CreatedAt,
        CreatedByPrincipal = actor,
        ModifiedByPrincipal = actor
    };

    private static Entitlement CreateEntitlement(ManagedResource resource, string code = "linux.admin") => new()
    {
        Resource = resource,
        Code = code,
        Name = code,
        MaxDurationMinutes = 60,
        IsActive = true
    };

    private sealed class ReadCommandCounter : DbCommandInterceptor
    {
        public int Count { get; private set; }

        public void Reset() => Count = 0;

        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
            DbCommand command,
            CommandEventData eventData,
            InterceptionResult<DbDataReader> result,
            CancellationToken cancellationToken = default)
        {
            Count++;
            return ValueTask.FromResult(result);
        }
    }
}
