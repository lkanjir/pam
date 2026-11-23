using Backend.IntegrationTests.Resources;
using Infrastructure.Persistence.Entities;

namespace Backend.IntegrationTests.Authorization;

internal static class BootstrapTestData
{
    public static async Task MarkActorAsync(ResourceTestContext test)
    {
        test.Database.Context.PamInstallations.Add(new PamInstallation
        {
            BootstrapPrincipalId = test.ActorId,
            InitializedAt = test.Clock.Now.UtcDateTime
        });
        await test.Database.Context.SaveChangesAsync();
    }

    public static async Task<string> InstallerAsync(string issuer = "https://identity.example/realms/pam",
        string subject = "bootstrap-subject", string name = "Temporary installer")
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "scripts", "initialize-pam.sql")))
        {
            directory = directory.Parent;
        }
        if (directory is null)
        {
            throw new InvalidOperationException("Repository installer script was not found.");
        }
        string script = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "scripts", "initialize-pam.sql"));
        return script.Replace("verified_issuer text := 'SET_VALIDATED_ISSUER';", $"verified_issuer text := '{Quote(issuer)}';", StringComparison.Ordinal)
            .Replace("verified_subject text := 'SET_VERIFIED_SUBJECT';", $"verified_subject text := '{Quote(subject)}';", StringComparison.Ordinal)
            .Replace("bootstrap_name text := 'SET_BOOTSTRAP_DISPLAY_NAME';", $"bootstrap_name text := '{Quote(name)}';", StringComparison.Ordinal);
    }

    private static string Quote(string value) => value.Replace("'", "''", StringComparison.Ordinal);
}
