using System.Security.Cryptography;
using System.Text;

namespace MyVpn.Core.Subscriptions;

/// <summary>
/// Computes the token that binds a user's consent to one exact provider-supplied value.
/// </summary>
/// <remarks>
/// <para>
/// A subscription header such as <c>tun-enable</c> asks the client to change behaviour, and the
/// design requires explicit user consent. Consent that is not bound to the value being consented
/// to is not consent: a provider could present a harmless-looking request, obtain a one-time
/// "yes", then change the value on the next refresh while the client kept applying the stored
/// approval. The token therefore hashes the subscription identity, the header name and a
/// fingerprint of the exact value, and any change to any of the three invalidates it.
/// </para>
/// <para>
/// This type is <b>public on purpose</b>. The algorithm was previously duplicated in the UI
/// because the original helper was internal — two copies of a security-relevant function, where a
/// change to one would silently invalidate every stored consent in the other. Exposing one
/// implementation is the fix; the UI no longer computes this itself.
/// </para>
/// </remarks>
public static class ConsentToken
{
    /// <summary>
    /// Computes the consent token for a <c>(subscription, header, value)</c> triple.
    /// </summary>
    /// <param name="subscriptionId">Stable identifier of the owning subscription.</param>
    /// <param name="headerName">Header name, compared case-insensitively.</param>
    /// <param name="valueFingerprint">SHA-256 fingerprint of the header value.</param>
    public static string Compute(string subscriptionId, string headerName, string valueFingerprint)
    {
        ArgumentNullException.ThrowIfNull(subscriptionId);
        ArgumentNullException.ThrowIfNull(headerName);
        ArgumentNullException.ThrowIfNull(valueFingerprint);

        // Newline-separated so that ("ab","c") and ("a","bc") cannot collide.
        var material = string.Concat(
            subscriptionId,
            "\n",
            headerName.ToLowerInvariant(),
            "\n",
            valueFingerprint);

        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(material));

        // Lowercase hex, matching every other fingerprint in this codebase.
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
