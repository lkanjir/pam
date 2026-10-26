using System.Globalization;
using Api.Configuration;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace Api.Authentication;

public sealed class PamSessionLifetime(IOptions<PamSessionOptions> options, TimeProvider timeProvider)
{
    private const string AbsoluteExpiresKey = "pam:absolute-expires-utc";

    public void Initialize(AuthenticationProperties properties)
    {
        // SigningIn and StoreAsync can both reach here. Preserve the original deadline.
        if (!properties.Items.ContainsKey(AbsoluteExpiresKey))
        {
            properties.Items[AbsoluteExpiresKey] = timeProvider.GetUtcNow()
                .Add(options.Value.AbsoluteTimeout).ToString("O", CultureInfo.InvariantCulture);
        }

        if (!TryLimitExpiration(properties))
            throw new InvalidOperationException("Authentication ticket must have a valid future session expiration.");
    }

    public bool TryLimitExpiration(AuthenticationProperties properties)
    {
        if (!TryGetAbsoluteExpiration(properties, out var absoluteExpiresAt)
            || properties.ExpiresUtc is not { } expiresAt)
            return false;

        var limitedExpiry = expiresAt < absoluteExpiresAt ? expiresAt : absoluteExpiresAt;
        if (limitedExpiry - timeProvider.GetUtcNow() < TimeSpan.FromMilliseconds(1))
            return false;

        properties.ExpiresUtc = limitedExpiry;
        return true;
    }

    public bool IsValid(AuthenticationProperties properties)
    {
        var now = timeProvider.GetUtcNow();
        return TryGetAbsoluteExpiration(properties, out var absoluteExpiresAt)
               && absoluteExpiresAt > now
               && properties.ExpiresUtc is { } expiresAt
               && expiresAt > now;
    }

    private static bool TryGetAbsoluteExpiration(AuthenticationProperties properties, out DateTimeOffset expiresAt)
    {
        properties.Items.TryGetValue(AbsoluteExpiresKey, out var value);
        return DateTimeOffset.TryParseExact(value, "O", CultureInfo.InvariantCulture,
            DateTimeStyles.None, out expiresAt);
    }
}
