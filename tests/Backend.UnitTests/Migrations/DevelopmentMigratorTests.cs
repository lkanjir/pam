using System.Globalization;
using Microsoft.Extensions.Configuration;
using Migrator;

namespace Backend.UnitTests.Migrations;

public sealed class DevelopmentMigratorTests
{
    [Theory]
    [InlineData("Production")]
    [InlineData("Staging")]
    [InlineData("")]
    public async Task Run_OutsideDevelopment_RefusesBeforeUsingConnection(string environment)
    {
        // Arrange
        var configuration = Configuration("Password=do-not-log;UnknownSetting=value");
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);

        // Act
        int result = await DevelopmentMigrator.RunAsync(configuration, environment, output, error);

        // Assert
        Assert.Equal(1, result);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Contains("can run only in Development", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("do-not-log", error.ToString(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    public async Task Run_MissingSharedConnection_ReturnsConfigurationError(string? connection)
    {
        // Arrange
        var configuration = Configuration(connection);
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);

        // Act
        int result = await DevelopmentMigrator.RunAsync(configuration, "Development", output, error);

        // Assert
        Assert.Equal(1, result);
        Assert.Contains("Database:ConnectionString is required", error.ToString(), StringComparison.Ordinal);
        Assert.Equal(string.Empty, output.ToString());
    }

    [Fact]
    public async Task Run_InvalidConnection_DoesNotExposeCredentials()
    {
        // Arrange
        var configuration = Configuration("Password=do-not-log;UnknownSetting=value");
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);

        // Act
        int result = await DevelopmentMigrator.RunAsync(configuration, "Development", output, error);

        // Assert
        Assert.Equal(1, result);
        Assert.Contains("Development migration failed", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("do-not-log", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("UnknownSetting", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("do-not-log", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Run_Cancelled_StopsBeforeDatabaseAccess()
    {
        // Arrange
        var configuration = Configuration("Host=127.0.0.1;Port=1;Password=do-not-log");
        using var output = new StringWriter(CultureInfo.InvariantCulture);
        using var error = new StringWriter(CultureInfo.InvariantCulture);
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        // Act
        int result = await DevelopmentMigrator.RunAsync(
            configuration, "Development", output, error, cancellation.Token);

        // Assert
        Assert.Equal(130, result);
        Assert.Equal(string.Empty, output.ToString());
        Assert.Contains("cancelled", error.ToString(), StringComparison.Ordinal);
    }

    private static IConfiguration Configuration(string? connection) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?> { ["Database:ConnectionString"] = connection }).Build();
}
