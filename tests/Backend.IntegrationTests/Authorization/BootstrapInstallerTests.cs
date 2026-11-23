using System.Text.Json;
using Backend.IntegrationTests.Fixtures;
using Backend.IntegrationTests.Sessions;
using Infrastructure.Identity;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Backend.IntegrationTests.Authorization;

[Collection(StorageCollection3.Name)]
public sealed class BootstrapInstallerTests(PostgresFixture postgres)
{
    [Fact]
    public async Task Initialize_VerifiedOpaqueIdentity_CreatesRestrictedAdminAndAtomicInstallationAudit()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        string script = await BootstrapTestData.InstallerAsync(subject: " opaque'Subject ");

        // Act
        await ExecuteAsync(database, script);

        // Assert
        var principal = await database.Context.Principals.SingleAsync();
        Assert.True(principal.IsEnabled);
        Assert.Equal(" opaque'Subject ", principal.Subject);
        Assert.Equal("Temporary installer", principal.DisplayName);
        Assert.NotEqual(Guid.Empty, principal.PublicId);
        var installation = await database.Context.PamInstallations.SingleAsync();
        Assert.Equal(1, installation.Id);
        Assert.Equal(principal.Id, installation.BootstrapPrincipalId);
        Assert.Null(installation.CompletedAt);
        Assert.Null(installation.CompletedByPrincipalId);
        var role = await database.Context.PamRoleAssignments.Include(value => value.Role).SingleAsync();
        Assert.Equal(principal.Id, role.PrincipalId);
        Assert.Equal("admin", role.Role.Code);
        var audit = await database.Context.AuditEvents.SingleAsync();
        Assert.Equal("bootstrap.initialized", audit.EventType);
        Assert.Equal("system", audit.ActorKind);
        Assert.Null(audit.ActorPrincipalId);
        Assert.Equal(principal.Id, audit.SubjectPrincipalId);
        Assert.Equal("pam.installer", audit.Source);
        Assert.Equal("success", audit.Outcome);
        Assert.Equal(installation.InitializedAt, audit.OccurredAt);
        Assert.False(string.IsNullOrEmpty(audit.CorrelationId));
        using var snapshot = JsonDocument.Parse(Assert.IsType<string>(audit.SubjectSnapshot));
        Assert.Equal(principal.PublicId, snapshot.RootElement.GetProperty("publicId").GetGuid());
        var identity = await new PrincipalIdentityReader(database.Context).FindAsync(principal.Issuer, principal.Subject);
        Assert.NotNull(identity);
        Assert.True(identity.IsBootstrap);
        Assert.True(identity.IsEnabled);
    }

    [Theory]
    [InlineData("SET_VALIDATED_ISSUER", "valid", "valid")]
    [InlineData("valid", "SET_VERIFIED_SUBJECT", "valid")]
    [InlineData("valid", "valid", "SET_BOOTSTRAP_DISPLAY_NAME")]
    [InlineData(" ", "valid", "valid")]
    [InlineData("valid", " ", "valid")]
    [InlineData("valid", "valid", " ")]
    public async Task Initialize_UnreviewedOrBlankIdentity_CreatesNoState(string issuer, string subject, string name)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        string script = await BootstrapTestData.InstallerAsync(issuer, subject, name);

        // Act / Assert
        await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(database, script));
        await AssertEmptyAsync(database);
    }

    [Fact]
    public async Task Initialize_AuditRejected_RollsBackIdentityRoleAndInstallation()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        await database.Context.Database.ExecuteSqlRawAsync(
            "ALTER TABLE audit_events ADD CONSTRAINT reject_installation CHECK (event_type <> 'bootstrap.initialized')");
        string script = await BootstrapTestData.InstallerAsync();

        // Act / Assert
        var error = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(database, script));
        Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
        await AssertEmptyAsync(database);
    }

    [Fact]
    public async Task Initialize_RepeatedOrConcurrentInstaller_OnlyOneIdentityAndAuditSurvive()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        string first = await BootstrapTestData.InstallerAsync(subject: "first");
        string second = await BootstrapTestData.InstallerAsync(subject: "second");

        // Act
        var results = await Task.WhenAll(TryInitializeAsync(database, first), TryInitializeAsync(database, second));

        // Assert
        Assert.Single(results, value => value);
        Assert.Single(results, value => !value);
        Assert.Equal(1, await database.Context.Principals.CountAsync());
        Assert.Equal(1, await database.Context.PamInstallations.CountAsync());
        Assert.Equal(1, await database.Context.PamRoleAssignments.CountAsync());
        Assert.Equal(1, await database.Context.AuditEvents.CountAsync());
        await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(database, first));
        Assert.Equal(1, await database.Context.AuditEvents.CountAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task Initialize_ExistingAdminIncludingDisabled_RefusesInstallation(bool enabled)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        string id = await SessionTestHost.SeedPrincipalAsync(database);
        long principalId = long.Parse(id, System.Globalization.CultureInfo.InvariantCulture);
        await SessionTestHost.AssignRolesAsync(database, principalId, "admin");
        await database.Context.Principals.Where(value => value.Id == principalId)
            .ExecuteUpdateAsync(update => update.SetProperty(value => value.IsEnabled, enabled));
        string script = await BootstrapTestData.InstallerAsync();

        // Act / Assert
        await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(database, script));
        Assert.Equal(1, await database.Context.Principals.CountAsync());
        Assert.False(await database.Context.PamInstallations.AnyAsync());
        Assert.False(await database.Context.AuditEvents.AnyAsync());
    }

    [Fact]
    public async Task Initialize_ExistingIdentityWithoutRole_RefusesAdoptingMapping()
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        await SessionTestHost.SeedPrincipalAsync(database);
        var principal = await database.Context.Principals.SingleAsync();
        string script = await BootstrapTestData.InstallerAsync(principal.Issuer, principal.Subject);

        // Act / Assert
        await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(database, script));
        Assert.Equal(1, await database.Context.Principals.CountAsync());
        Assert.False(await database.Context.PamInstallations.AnyAsync());
        Assert.False(await database.Context.PamRoleAssignments.AnyAsync());
    }

    private static async Task ExecuteAsync(TestDatabase database, string script)
    {
        // Separate administrator connection closes (and rolls back) on any failed script.
        await using var connection = new NpgsqlConnection(database.Context.Database.GetConnectionString());
        await connection.OpenAsync();
        await using var command = new NpgsqlCommand(script, connection);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<bool> TryInitializeAsync(TestDatabase database, string script)
    {
        try
        {
            await ExecuteAsync(database, script);
            return true;
        }
        catch (PostgresException exception) when (exception.SqlState == PostgresErrorCodes.RaiseException)
        {
            return false;
        }
    }

    private static async Task AssertEmptyAsync(TestDatabase database)
    {
        Assert.False(await database.Context.Principals.AnyAsync());
        Assert.False(await database.Context.PamRoles.AnyAsync());
        Assert.False(await database.Context.PamRoleAssignments.AnyAsync());
        Assert.False(await database.Context.PamInstallations.AnyAsync());
        Assert.False(await database.Context.AuditEvents.AnyAsync());
    }
}
