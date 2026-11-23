namespace Backend.IntegrationTests.Fixtures;

// Independent container pairs allow these collections to run concurrently.
// Tests inside a collection remain sequential; each test creates its own database.
[CollectionDefinition(Name)]
public sealed class StorageCollection1 : ICollectionFixture<PostgresFixture>, ICollectionFixture<RedisFixture>
{
    public const string Name = "Storage 1";
}

[CollectionDefinition(Name)]
public sealed class StorageCollection2 : ICollectionFixture<PostgresFixture>, ICollectionFixture<RedisFixture>
{
    public const string Name = "Storage 2";
}

[CollectionDefinition(Name)]
public sealed class StorageCollection3 : ICollectionFixture<PostgresFixture>, ICollectionFixture<RedisFixture>
{
    public const string Name = "Storage 3";
}

[CollectionDefinition(Name)]
public sealed class StorageCollection4 : ICollectionFixture<PostgresFixture>, ICollectionFixture<RedisFixture>
{
    public const string Name = "Storage 4";
}
