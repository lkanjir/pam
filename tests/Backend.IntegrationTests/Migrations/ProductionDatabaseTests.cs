using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Backend.IntegrationTests.Migrations;

public sealed class ProductionDatabaseTests
{
    [Fact]
    public async Task Apply_ReviewedSqlTwice_CreatesCurrentSchemaWithoutMigrator()
    {
        // Arrange
        await using var database = await MigrationDatabase.StartAsync(bootstrap: false);
        await using var context = database.Context(admin: true);
        string sql = context.GetService<IMigrator>().GenerateScript(options: MigrationsSqlGenerationOptions.Idempotent);

        // Act
        await database.ExecuteAdminAsync(sql);
        await database.ExecuteAdminAsync(sql);

        // Assert
        var expected = context.Database.GetMigrations().ToArray();
        Assert.NotEmpty(expected);
        Assert.Equal(expected, await context.Database.GetAppliedMigrationsAsync());
    }
}
