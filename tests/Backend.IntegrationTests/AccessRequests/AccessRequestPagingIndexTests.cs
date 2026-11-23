using Backend.IntegrationTests.Fixtures;
using Microsoft.EntityFrameworkCore;
using Npgsql;

namespace Backend.IntegrationTests.AccessRequests;

public sealed class AccessRequestPagingIndexTests(PostgresFixture postgres) : IClassFixture<PostgresFixture>
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task OwnRequestPaging_MigratedIndex_SupportsOwnerAndDescendingCursorWithoutSort(bool cursor)
    {
        // Arrange
        await using var database = await postgres.CreateDatabaseAsync();
        await using var connection = new NpgsqlConnection(database.Context.Database.GetConnectionString());
        await connection.OpenAsync();
        await using var transaction = await connection.BeginTransactionAsync();
        // Verify the available ordered index path, independently of empty-table cost estimates.
        await using (var setting = new NpgsqlCommand("SET LOCAL enable_seqscan = off; SET LOCAL enable_bitmapscan = off", connection, transaction))
        {
            await setting.ExecuteNonQueryAsync();
        }
        string sql = cursor
            ? "EXPLAIN SELECT public_id FROM access_requests WHERE requester_principal_id = @owner AND public_id < @cursor ORDER BY public_id DESC LIMIT 21"
            : "EXPLAIN SELECT public_id FROM access_requests WHERE requester_principal_id = @owner ORDER BY public_id DESC LIMIT 21";
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        command.Parameters.AddWithValue("owner", 1L);
        if (cursor)
        {
            command.Parameters.AddWithValue("cursor", Guid.Parse("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        }

        // Act
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<string>();
        while (await reader.ReadAsync())
        {
            rows.Add(reader.GetString(0));
        }
        string plan = string.Join('\n', rows);

        // Assert
        Assert.Contains("Index Only Scan Backward using ix_access_requests_requester_principal_id_public_id", plan, StringComparison.Ordinal);
        Assert.Contains("Index Cond:", plan, StringComparison.Ordinal);
        Assert.Contains("requester_principal_id =", plan, StringComparison.Ordinal);
        Assert.DoesNotContain("Sort", plan, StringComparison.Ordinal);
        if (cursor)
        {
            Assert.Contains("public_id <", plan, StringComparison.Ordinal);
        }
    }
}
