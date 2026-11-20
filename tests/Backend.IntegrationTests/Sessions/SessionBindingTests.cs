using Application.Sessions;
using Backend.IntegrationTests.Fixtures;
using Backend.Tests.Support;
using Infrastructure.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace Backend.IntegrationTests.Sessions;

public sealed class SessionBindingTests(RedisFixture redis) : IClassFixture<RedisFixture>
{
    [Fact]
    public async Task Store_FrameworkTicketMetadata_ContainsOnlyTheActualSessionHash()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        var ticket = SessionTestData.Ticket(clock.Now);
        ticket.Properties.Items[SessionTicketMetadata.SessionIdHash] = "caller-value";

        // Act
        string id = await store.StoreAsync(ticket);
        var retrieved = await store.RetrieveAsync(id);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(SessionIdentifier.Hash(id), retrieved.Properties.GetString(SessionTicketMetadata.SessionIdHash));
        Assert.NotEqual(id, retrieved.Properties.GetString(SessionTicketMetadata.SessionIdHash));
        await store.DiscardUnissuedAsync(id);
    }

    [Fact]
    public async Task Retrieve_LegacyTicketWithUntrustedMetadata_DerivesBindingFromTheActualKey()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var protection = new EphemeralDataProtectionProvider();
        var store = new RedisTicketStore(redis.Connection, protection, clock);
        string id = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        string key = SessionTestData.RedisKey(id);
        var legacy = SessionTestData.Ticket(clock.Now);
        legacy.Properties.Items[SessionTicketMetadata.SessionIdHash] = "forged-metadata";
        var protectedTicket = protection.CreateProtector("Pam.RedisTicketStore").CreateProtector(key)
            .Protect(TicketSerializer.Default.Serialize(legacy));
        await redis.Connection.GetDatabase().StringSetAsync(key, protectedTicket, TimeSpan.FromMinutes(30));

        // Act
        var retrieved = await store.RetrieveAsync(id);

        // Assert
        Assert.NotNull(retrieved);
        Assert.Equal(SessionIdentifier.Hash(id), retrieved.Properties.GetString(SessionTicketMetadata.SessionIdHash));
        Assert.Equal("Ana Horvat", retrieved.Principal.FindFirst("name")?.Value);
        await store.DiscardUnissuedAsync(id);
    }

    [Fact]
    public async Task Renew_ReplacementTicket_CannotReplaceItsSessionBindingWithCallerMetadata()
    {
        // Arrange
        var clock = new TestTimeProvider();
        var store = new RedisTicketStore(redis.Connection, new EphemeralDataProtectionProvider(), clock);
        string id = await store.StoreAsync(SessionTestData.Ticket(clock.Now));
        clock.Now = clock.Now.AddMinutes(16);
        var renewed = SessionTestData.Ticket(clock.Now);
        renewed.Properties.Items[SessionTicketMetadata.SessionIdHash] = new string('F', 64);

        // Act
        bool replaced = await store.TryRenewAsync(id, renewed);
        var retrieved = await store.RetrieveAsync(id);

        // Assert
        Assert.True(replaced);
        Assert.NotNull(retrieved);
        Assert.Equal(SessionIdentifier.Hash(id), retrieved.Properties.GetString(SessionTicketMetadata.SessionIdHash));
        Assert.Equal(clock.Now.AddMinutes(30), retrieved.Properties.ExpiresUtc);
        await store.DiscardUnissuedAsync(id);
    }
}
