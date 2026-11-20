using System.Text.Json;
using System.Text.Json.Serialization;
using Application.Sessions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace Api.Authentication;

internal static class PamReauthentication
{
    private const string BindingKey = "pam:reauthentication-binding";

    public static bool IsRequested(AuthenticationProperties? properties) => properties?.Items.ContainsKey(BindingKey) == true;

    public static OpenIdConnectChallengeProperties CreateChallenge(PamUserIdentity identity, string sessionIdHash)
    {
        var properties = new OpenIdConnectChallengeProperties { MaxAge = TimeSpan.Zero, RedirectUri = "/api/me" };
        properties.Items[BindingKey] = JsonSerializer.Serialize(new Binding(identity.PublicId,
            identity.Issuer, identity.Subject, sessionIdHash));
        return properties;
    }

    public static bool TryRead(AuthenticationProperties? properties, out Binding? binding)
    {
        binding = null;
        if (properties is null || !properties.Items.TryGetValue(BindingKey, out string? json) || json is null)
        {
            return false;
        }
        try
        {
            binding = JsonSerializer.Deserialize<Binding>(json);
        }
        catch (JsonException)
        {
            return false;
        }

        return binding is not null && binding.PrincipalId != Guid.Empty
            && !string.IsNullOrWhiteSpace(binding.Issuer) && !string.IsNullOrWhiteSpace(binding.Subject)
            && SessionIdentifier.IsValid(binding.SessionIdHash);
    }

    public static void Clear(AuthenticationProperties? properties) => properties?.Items.Remove(BindingKey);

    internal sealed record Binding(
        [property: JsonRequired] Guid PrincipalId,
        [property: JsonRequired] string Issuer,
        [property: JsonRequired] string Subject,
        [property: JsonRequired] string SessionIdHash);
}
