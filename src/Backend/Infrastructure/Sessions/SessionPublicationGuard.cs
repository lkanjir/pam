using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.Sessions;

// Both publication and orphan cleanup hold this transaction-scoped PostgreSQL
// lock. Hash collisions only serialize otherwise unrelated sessions.
internal static class SessionPublicationGuard
{
    public static Task<int> LockAsync(PamDbContext database, string sessionIdHash, CancellationToken cancellationToken) =>
        database.Database.ExecuteSqlAsync(
            $"SELECT pg_advisory_xact_lock(hashtextextended({sessionIdHash}, 0))", cancellationToken);
}
