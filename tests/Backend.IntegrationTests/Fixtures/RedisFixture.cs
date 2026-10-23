using StackExchange.Redis;
using Testcontainers.Redis;

namespace Backend.IntegrationTests.Fixtures;

public sealed class RedisFixture : IAsyncLifetime
{
    private readonly RedisContainer _container = new RedisBuilder("redis:8.2.2-alpine").Build();
    public IConnectionMultiplexer Connection { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _container.StartAsync();
        Connection = await ConnectionMultiplexer.ConnectAsync(_container.GetConnectionString());
    }

    public async Task DisposeAsync()
    {
        Connection?.Dispose();
        await _container.DisposeAsync();
    }
}
