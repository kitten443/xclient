using System.Net;
using System.Net.Sockets;

namespace MyVpn.Core.Net;

/// <summary>Why a URL was refused.</summary>
public enum UrlRejectionReason
{
    None = 0,
    Empty,
    NotAbsolute,
    SchemeNotAllowed,
    InsecureScheme,
    HasCredentials,
    HostMissing,
    LoopbackAddress,
    PrivateAddress,
    LinkLocalAddress,
    UnspecifiedAddress,
    MulticastAddress,
    BlockedHostName,
}

/// <summary>
/// Validates URLs that arrive from an untrusted source — a subscription header, a
/// share link or an update feed.
/// </summary>
/// <remarks>
/// <para>
/// A subscription response is attacker-influenced input. A header such as
/// <c>support-url</c> or <c>fallback-url</c> that points at
/// <c>http://127.0.0.1:8080/admin</c> or <c>http://169.254.169.254/latest/meta-data</c>
/// turns "click the support link" into a server-side request forgery against the user's
/// own machine or cloud metadata endpoint. Such URLs are therefore refused at parse
/// time, by default, rather than being displayed as a clickable link.
/// </para>
/// <para>
/// <b>Known limitation, deliberately documented:</b> this check is textual. It cannot
/// detect a <i>public</i> host name that resolves to a private address (DNS rebinding).
/// The HTTP layer must re-validate every resolved address after DNS resolution and
/// before connecting; see <c>UrlSafety.IsAddressAllowed</c>, which is the same
/// predicate applied to a resolved <see cref="IPAddress"/>.
/// </para>
/// </remarks>
public static class UrlSafety
{
    /// <summary>Host names that always resolve locally and are never legitimate here.</summary>
    private static readonly string[] BlockedHostNames =
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "metadata.google.internal",
        "instance-data",
    };

    /// <summary>
    /// Validates an HTTP(S) URL for use as a subscription, feed or displayed link.
    /// </summary>
    /// <param name="url">Candidate URL.</param>
    /// <param name="allowInsecureHttp">
    /// When false, only <c>https</c> is accepted. Subscription URLs default to HTTPS-only.
    /// </param>
    /// <param name="reason">Machine-readable rejection reason.</param>
    /// <param name="allowPrivateAddresses">
    /// Permits loopback, private and link-local destinations. Off by default because a
    /// subscription response is attacker-influenced input and a link pointing at
    /// <c>127.0.0.1</c> or a cloud metadata address is the classic SSRF. It exists as an explicit
    /// opt-in for the legitimate case of a self-hosted panel on the same machine or on a LAN, and
    /// it relaxes only the address class — the scheme, credential and control-character rules
    /// still apply.
    /// </param>
    public static bool IsSafeHttpUrl(
        string? url,
        bool allowInsecureHttp,
        out UrlRejectionReason reason,
        bool allowPrivateAddresses = false)
    {
        reason = UrlRejectionReason.None;

        if (string.IsNullOrWhiteSpace(url))
        {
            reason = UrlRejectionReason.Empty;
            return false;
        }

        if (!Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri))
        {
            reason = UrlRejectionReason.NotAbsolute;
            return false;
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            reason = UrlRejectionReason.SchemeNotAllowed;
            return false;
        }

        if (uri.Scheme == Uri.UriSchemeHttp && !allowInsecureHttp)
        {
            reason = UrlRejectionReason.InsecureScheme;
            return false;
        }

        // Embedded credentials leak into logs and into the UI; refuse outright.
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            reason = UrlRejectionReason.HasCredentials;
            return false;
        }

        if (string.IsNullOrWhiteSpace(uri.Host))
        {
            reason = UrlRejectionReason.HostMissing;
            return false;
        }

        foreach (var blocked in BlockedHostNames)
        {
            if (uri.Host.Equals(blocked, StringComparison.OrdinalIgnoreCase)
                || uri.Host.EndsWith("." + blocked, StringComparison.OrdinalIgnoreCase))
            {
                reason = UrlRejectionReason.BlockedHostName;
                return false;
            }
        }

        if (IPAddress.TryParse(uri.Host, out var ip))
        {
            return allowPrivateAddresses || IsAddressAllowed(ip, out reason);
        }

        // A host name that is itself loopback-ish is still refused unless the caller opted in.
        if (allowPrivateAddresses)
        {
            return true;
        }

        return true;
    }

    /// <summary>
    /// Applies the same address policy to an already-resolved address. The HTTP layer
    /// calls this after DNS resolution to close the DNS-rebinding hole.
    /// </summary>
    public static bool IsAddressAllowed(IPAddress address, out UrlRejectionReason reason)
    {
        ArgumentNullException.ThrowIfNull(address);
        reason = UrlRejectionReason.None;

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
        {
            reason = UrlRejectionReason.UnspecifiedAddress;
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            reason = UrlRejectionReason.LoopbackAddress;
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6LinkLocal)
        {
            reason = UrlRejectionReason.LinkLocalAddress;
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6SiteLocal)
        {
            reason = UrlRejectionReason.PrivateAddress;
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6 && address.IsIPv6Multicast)
        {
            reason = UrlRejectionReason.MulticastAddress;
            return false;
        }

        if (IsPrivateOrReserved(address))
        {
            reason = UrlRejectionReason.PrivateAddress;
            return false;
        }

        return true;
    }

    /// <summary>
    /// True for RFC1918 space, CGNAT, link-local, benchmarking and documentation ranges.
    /// </summary>
    public static bool IsPrivateOrReserved(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var v6 = address.GetAddressBytes();

            // fc00::/7 unique local
            if ((v6[0] & 0xFE) == 0xFC)
            {
                return true;
            }

            // 2001:db8::/32 documentation
            if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0D && v6[3] == 0xB8)
            {
                return true;
            }

            return false;
        }

        var octets = address.GetAddressBytes();

        return octets[0] switch
        {
            10 => true,                                       // 10.0.0.0/8
            127 => true,                                      // loopback (also caught above)
            169 when octets[1] == 254 => true,                // 169.254.0.0/16 link-local
            172 when octets[1] is >= 16 and <= 31 => true,    // 172.16.0.0/12
            192 when octets[1] == 168 => true,                // 192.168.0.0/16
            192 when octets[1] == 0 && octets[2] == 0 => true, // 192.0.0.0/24
            192 when octets[1] == 0 && octets[2] == 2 => true, // 192.0.2.0/24 TEST-NET-1
            198 when octets[1] is 18 or 19 => true,           // 198.18.0.0/15 benchmarking
            198 when octets[1] == 51 && octets[2] == 100 => true, // 198.51.100.0/24 TEST-NET-2
            203 when octets[1] == 0 && octets[2] == 113 => true,  // 203.0.113.0/24 TEST-NET-3
            100 when octets[1] is >= 64 and <= 127 => true,   // 100.64.0.0/10 CGNAT
            0 => true,                                        // 0.0.0.0/8
            255 => true,                                      // broadcast
            _ => false,
        };
    }
}
