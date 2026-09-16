using System.Net;
using System.Net.Sockets;

namespace MyVpn.Core.Net;

/// <summary>
/// An IPv4 or IPv6 CIDR block, used for routing rules and Kill Switch exclusions.
/// </summary>
/// <remarks>
/// Implemented here rather than taking a dependency on a networking helper package
/// because the semantics we need are specific and must be exact: a Kill Switch that
/// mis-computes a prefix by one bit either leaks traffic or blackholes the tunnel.
/// The type is a value type, immutable, and fully unit tested, including the
/// IPv4-mapped-IPv6 and <c>/0</c> cases.
/// </remarks>
public readonly struct CidrBlock : IEquatable<CidrBlock>
{
    public CidrBlock(IPAddress network, int prefixLength)
    {
        ArgumentNullException.ThrowIfNull(network);

        var maxPrefix = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        if (prefixLength < 0 || prefixLength > maxPrefix)
        {
            throw new ArgumentOutOfRangeException(
                nameof(prefixLength),
                prefixLength,
                $"Prefix length must be between 0 and {maxPrefix} for {network.AddressFamily}.");
        }

        var masked = MaskBytes(network.GetAddressBytes(), prefixLength);
        Network = new IPAddress(masked);
        PrefixLength = prefixLength;
        _masked = masked;
    }

    private readonly byte[] _masked;

    /// <summary>The network address with host bits cleared.</summary>
    public IPAddress Network { get; }

    public int PrefixLength { get; }

    public AddressFamily AddressFamily => Network.AddressFamily;

    public bool IsIPv4 => Network.AddressFamily == AddressFamily.InterNetwork;

    public bool IsIPv6 => Network.AddressFamily == AddressFamily.InterNetworkV6;

    /// <summary>
    /// Parses <c>10.0.0.0/8</c>, bare <c>10.0.0.1</c> (treated as a host route, /32 or
    /// /128) and IPv6 forms including bracketed ones.
    /// </summary>
    public static bool TryParse(string? text, out CidrBlock block)
    {
        block = default;

        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();

        // Tolerate a bracketed IPv6 literal, e.g. "[2001:db8::1]/64".
        var slash = value.LastIndexOf('/');
        var addressPart = slash >= 0 ? value[..slash] : value;
        var prefixPart = slash >= 0 ? value[(slash + 1)..] : null;

        if (addressPart.Length > 1 && addressPart[0] == '[' && addressPart[^1] == ']')
        {
            addressPart = addressPart[1..^1];
        }

        if (!IPAddress.TryParse(addressPart, out var address))
        {
            return false;
        }

        // Normalize IPv4-mapped IPv6 (::ffff:1.2.3.4) so prefix math uses 32 bits.
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        var maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

        var prefix = maxPrefix;
        if (prefixPart is not null)
        {
            if (!int.TryParse(prefixPart, System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out prefix))
            {
                return false;
            }

            if (prefix < 0 || prefix > maxPrefix)
            {
                return false;
            }
        }

        block = new CidrBlock(address, prefix);
        return true;
    }

    public static CidrBlock Parse(string text) =>
        TryParse(text, out var block)
            ? block
            : throw new FormatException($"Not a valid CIDR block: '{text}'.");

    /// <summary>True when <paramref name="address"/> falls inside this block.</summary>
    public bool Contains(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (address.AddressFamily != Network.AddressFamily)
        {
            return false;
        }

        var candidate = address.GetAddressBytes();
        if (candidate.Length != _masked.Length)
        {
            return false;
        }

        // Compare only whole bytes fully covered by the prefix, then the partial byte.
        var fullBytes = PrefixLength / 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (candidate[i] != _masked[i])
            {
                return false;
            }
        }

        var remainingBits = PrefixLength % 8;
        if (remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (candidate[fullBytes] & mask) == (_masked[fullBytes] & mask);
    }

    public bool Contains(CidrBlock other) =>
        other.AddressFamily == AddressFamily && PrefixLength <= other.PrefixLength && Contains(other.Network);

    public bool Equals(CidrBlock other) =>
        PrefixLength == other.PrefixLength
        && (_masked is null ? other._masked is null : other._masked is not null && _masked.AsSpan().SequenceEqual(other._masked));

    public override bool Equals(object? obj) => obj is CidrBlock other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(PrefixLength);
        if (_masked is not null)
        {
            foreach (var b in _masked)
            {
                hash.Add(b);
            }
        }

        return hash.ToHashCode();
    }

    public static bool operator ==(CidrBlock left, CidrBlock right) => left.Equals(right);

    public static bool operator !=(CidrBlock left, CidrBlock right) => !left.Equals(right);

    public override string ToString() => $"{Network}/{PrefixLength}";

    private static byte[] MaskBytes(byte[] address, int prefixLength)
    {
        var result = new byte[address.Length];
        Array.Copy(address, result, address.Length);

        var fullBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        if (remainingBits > 0 && fullBytes < result.Length)
        {
            result[fullBytes] &= (byte)(0xFF << (8 - remainingBits));
            fullBytes++;
        }

        for (var i = fullBytes; i < result.Length; i++)
        {
            result[i] = 0;
        }

        return result;
    }
}
