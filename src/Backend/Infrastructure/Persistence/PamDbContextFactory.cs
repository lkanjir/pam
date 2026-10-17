using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Infrastructure.Persistence;

public class PamDbContextFactory : IDesignTimeDbContextFactory<PamDbContext>
{
    public PamDbContext CreateDbContext(string[] args)
    {
        var connectionString = Environment.GetEnvironmentVariable("PAM_MIGRATIONS_CONNECTION") ??
                               "Host=localhost;Port=1;Database=design_only;Username=design_only";
        var options = new DbContextOptionsBuilder<PamDbContext>().UseNpgsql(connectionString)
            .UseSnakeCaseNamingConvention().Options;

        return new PamDbContext(options);
    }
}