using Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Npgsql;

static string Required(string name) =>
    Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value
        : throw new InvalidOperationException($"Required environment variable: {name}");

try
{
    var connectionString = new NpgsqlConnectionStringBuilder
    {
        Host = Required("DB_HOST"),
        Database = Required("POSTGRES_DB"),
        Username = Required("POSTGRES_USER"),
        Password = Required("POSTGRES_PASSWORD"),
        // The local stack uses password authentication, not Kerberos.
        GssEncryptionMode = GssEncryptionMode.Disable
    }.ConnectionString;
    var appUser = Required("APP_DB_USER");
    var options = new DbContextOptionsBuilder<PamDbContext>()
        .UseNpgsql(connectionString)
        .UseSnakeCaseNamingConvention()
        .Options;

    await using var db = new PamDbContext(options);
    Console.WriteLine("Applying pending database migrations...");
    await db.Database.MigrateAsync();

    // Default privileges are installed by PostgreSQL initialization. Restrict
    // these exceptions before the API is allowed to start.
    using var commandBuilder = new NpgsqlCommandBuilder();
    var role = commandBuilder.QuoteIdentifier(appUser);
    await using var connection = new NpgsqlConnection(connectionString);
    await connection.OpenAsync();
    await using var command = new NpgsqlCommand($"""
        REVOKE ALL ON TABLE public."__EFMigrationsHistory" FROM {role};
        REVOKE UPDATE, DELETE ON TABLE public.audit_events FROM {role};
        """, connection);
    await command.ExecuteNonQueryAsync();
    Console.WriteLine("Database migrations and application permissions are ready.");
    return 0;
}
catch (Exception exception)
{
    // Avoid logging credentials, connection strings or SQL parameter values.
    Console.Error.WriteLine($"Migration failed ({exception.GetType().Name}). API startup is blocked.");
    if (exception is PostgresException postgresException)
        Console.Error.WriteLine($"PostgreSQL SQLSTATE: {postgresException.SqlState}");
    return 1;
}
