using Microsoft.AspNetCore.Authentication;

namespace Infrastructure.Authentication;

// Storage contract for protected authentication tickets. The API's ITicketStore
// adapter owns session lifetime policy and ledger/audit coordination.
public interface ISessionTicketStore
{
    Task<string> StoreAsync(AuthenticationTicket ticket);
    Task<AuthenticationTicket?> RetrieveAsync(string key);
    // Returns false when missing, expired, superseded or unable to win contention.
    // Must never shorten expiry or recreate a removed session.
    Task<bool> TryRenewAsync(string key, AuthenticationTicket ticket);
    Task RemoveAsync(string key);
}
