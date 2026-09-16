using System.Security.Cryptography;
using System.Text;

namespace MyVpn.Core.Subscriptions;

/// <summary>Bounds applied to every subscription response header.</summary>
/// <remarks>
/// A hostile or merely broken provider can return hundreds of headers or a single
/// multi-megabyte value. Every one of these bounds must exist, because the header bag
/// is built before any trust decision is made.
/// </remarks>
public sealed record HeaderLimits
{
    public static readonly HeaderLimits Default = new();

    public int MaxHeaderCount { get; init; } = 128;

    public int MaxNameLength { get; init; } = 128;

    public int MaxValueLength { get; init; } = 8192;

    public int MaxTotalBytes { get; init; } = 65_536;
}

/// <summary>A header that was accepted into the bag.</summary>
/// <param name="Name">Original name, as received.</param>
/// <param name="Value">Original value, as received (never re-encoded).</param>
/// <param name="ValueFingerprint">
/// Lowercase hex SHA-256 of the value. Used to bind user consent to an exact value, so
/// that a provider cannot obtain consent once and then change the value behind it.
/// The fingerprint is stored instead of nothing at all so that "did this change?"
/// remains answerable without retaining sensitive content in logs.
/// </param>
/// <param name="IsKnown">True when a registered parser claims this header.</param>
public sealed record RawHeader(string Name, string Value, string ValueFingerprint, bool IsKnown);

/// <summary>A header that was dropped before parsing, with the reason.</summary>
public sealed record RejectedHeader(string Name, int Length, string ReasonCode, string ReasonKey);

/// <summary>
/// Case-insensitive, bounded, injection-resistant snapshot of subscription response headers.
/// </summary>
/// <remarks>
/// <para>
/// This is the only place raw headers enter the application. Two properties matter:
/// </para>
/// <list type="number">
/// <item><description>
/// <b>Nothing is silently dropped.</b> A header that fails validation is recorded in
/// <see cref="Rejected"/> with a machine-readable reason, so diagnostics can explain
/// exactly why a provider's title or quota did not appear.
/// </description></item>
/// <item><description>
/// <b>Unknown headers are preserved but inert.</b> They are retained as opaque strings
/// with a fingerprint, and no code path ever interprets them as configuration. That is
/// what allows forward compatibility with a header we have never heard of without
/// letting a provider drive the client.
/// </description></item>
/// </list>
/// </remarks>
public sealed class RawHeaderBag
{
    private readonly Dictionary<string, List<RawHeader>> _byName;
    private readonly List<RawHeader> _ordered;

    private RawHeaderBag(
        Dictionary<string, List<RawHeader>> byName,
        List<RawHeader> ordered,
        List<RejectedHeader> rejected,
        int totalBytes)
    {
        _byName = byName;
        _ordered = ordered;
        Rejected = rejected;
        TotalBytes = totalBytes;
    }

    public static RawHeaderBag Empty { get; } = new(
        new Dictionary<string, List<RawHeader>>(StringComparer.OrdinalIgnoreCase),
        new List<RawHeader>(),
        new List<RejectedHeader>(),
        0);

    /// <summary>All accepted headers, in the order received.</summary>
    public IReadOnlyList<RawHeader> All => _ordered;

    /// <summary>Headers dropped during construction.</summary>
    public IReadOnlyList<RejectedHeader> Rejected { get; }

    /// <summary>Total bytes of accepted values.</summary>
    public int TotalBytes { get; }

    public int Count => _ordered.Count;

    /// <summary>Accepted headers no parser claims.</summary>
    public IEnumerable<RawHeader> Unknown => _ordered.Where(h => !h.IsKnown);

    /// <summary>Distinct accepted header names.</summary>
    public IEnumerable<string> Names => _ordered.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Builds a bag from raw pairs, applying every bound.
    /// </summary>
    /// <param name="pairs">Headers as returned by the HTTP layer.</param>
    /// <param name="knownNames">Names claimed by registered parsers.</param>
    /// <param name="limits">Bounds; defaults are used when omitted.</param>
    public static RawHeaderBag FromPairs(
        IEnumerable<KeyValuePair<string, string>>? pairs,
        ISet<string>? knownNames = null,
        HeaderLimits? limits = null)
    {
        var effectiveLimits = limits ?? HeaderLimits.Default;
        var byName = new Dictionary<string, List<RawHeader>>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<RawHeader>();
        var rejected = new List<RejectedHeader>();
        var totalBytes = 0;

        if (pairs is null)
        {
            return Empty;
        }

        foreach (var pair in pairs)
        {
            var name = pair.Key ?? string.Empty;
            var value = pair.Value ?? string.Empty;

            if (name.Length == 0)
            {
                rejected.Add(new RejectedHeader(name, value.Length, "empty_name", "error.header.empty_name"));
                continue;
            }

            if (name.Length > effectiveLimits.MaxNameLength)
            {
                rejected.Add(new RejectedHeader(
                    Truncate(name, 64), name.Length, "name_too_long", "error.header.name_too_long"));
                continue;
            }

            if (!IsValidToken(name))
            {
                rejected.Add(new RejectedHeader(
                    Truncate(name, 64), name.Length, "invalid_name", "error.header.invalid_name"));
                continue;
            }

            if (value.Length > effectiveLimits.MaxValueLength)
            {
                rejected.Add(new RejectedHeader(
                    Truncate(name, 64), value.Length, "value_too_long", "error.header.value_too_long"));
                continue;
            }

            // Rejecting control characters here, before any parser sees the value, is
            // what prevents header-injection style attacks from reaching a consumer that
            // might write the value into a config file, a log line or a UI label.
            if (ContainsControlCharacter(value))
            {
                rejected.Add(new RejectedHeader(
                    Truncate(name, 64), value.Length, "control_characters", "error.header.control_characters"));
                continue;
            }

            if (ordered.Count >= effectiveLimits.MaxHeaderCount)
            {
                rejected.Add(new RejectedHeader(
                    Truncate(name, 64), value.Length, "too_many_headers", "error.header.too_many"));
                continue;
            }

            if (totalBytes + value.Length > effectiveLimits.MaxTotalBytes)
            {
                rejected.Add(new RejectedHeader(
                    Truncate(name, 64), value.Length, "total_size_exceeded", "error.header.total_size"));
                continue;
            }

            var header = new RawHeader(
                Name: name,
                Value: value,
                ValueFingerprint: Fingerprint(value),
                IsKnown: knownNames is not null && knownNames.Contains(name));

            if (!byName.TryGetValue(name, out var list))
            {
                list = new List<RawHeader>(1);
                byName[name] = list;
            }

            list.Add(header);
            ordered.Add(header);
            totalBytes += value.Length;
        }

        return new RawHeaderBag(byName, ordered, rejected, totalBytes);
    }

    /// <summary>All values for a header name, in received order.</summary>
    public IReadOnlyList<string> GetValues(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return _byName.TryGetValue(name, out var list)
            ? list.Select(h => h.Value).ToArray()
            : Array.Empty<string>();
    }

    /// <summary>All accepted entries for a header name.</summary>
    public IReadOnlyList<RawHeader> GetEntries(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return _byName.TryGetValue(name, out var list)
            ? list.ToArray()
            : Array.Empty<RawHeader>();
    }

    public bool Contains(string name)
    {
        ArgumentNullException.ThrowIfNull(name);
        return _byName.ContainsKey(name);
    }

    /// <summary>
    /// Single value for a header name, or <c>null</c>. Returns <c>null</c> when the
    /// header appears more than once, because choosing one arbitrarily is exactly the
    /// "last wins" behaviour that lets a provider override an earlier security-relevant
    /// value. Parsers that must handle duplicates use <see cref="GetValues"/> and apply
    /// an explicit <c>DuplicatePolicy</c>.
    /// </summary>
    public string? GetSingle(string name)
    {
        var entries = GetEntries(name);
        return entries.Count == 1 ? entries[0].Value : null;
    }

    private static bool ContainsControlCharacter(string value)
    {
        foreach (var c in value)
        {
            if (c < 0x20 || c == 0x7F)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>RFC 9110 field-name token validation.</summary>
    private static bool IsValidToken(string name)
    {
        foreach (var c in name)
        {
            var ok = char.IsAsciiLetterOrDigit(c)
                     || c is '!' or '#' or '$' or '%' or '&' or '\'' or '*' or '+' or '-'
                         or '.' or '^' or '_' or '`' or '|' or '~';

            if (!ok)
            {
                return false;
            }
        }

        return name.Length > 0;
    }

    private static string Fingerprint(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value));

        // Lowercase hex: Convert.ToHexStringLower is .NET 9+, so lower explicitly.
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max];
}
