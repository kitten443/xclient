using System.Globalization;

namespace MyVpn.Core.Subscriptions;

/// <summary>
/// Traffic counters and expiry reported by a subscription provider.
/// </summary>
/// <remarks>
/// <para>
/// Serialized form is a single header, documented by Happ as
/// <c>upload=…; download=…; total=…; expire=…</c>. The parser is tolerant of the
/// variations seen in the wild (comma separators, surrounding whitespace, quoted
/// values, float byte counts) because panels that emit this header are not consistent,
/// but it never invents a value it could not read.
/// </para>
/// <para>
/// Units and the special values are worth stating explicitly because they are
/// conventions rather than a published specification:
/// <list type="bullet">
/// <item><description><c>upload</c>/<c>download</c>/<c>total</c> are bytes.</description></item>
/// <item><description><c>expire</c> is Unix seconds.</description></item>
/// <item><description><c>total=0</c> means unlimited, <c>expire=0</c> means no expiry.</description></item>
/// </list>
/// </para>
/// </remarks>
public sealed record SubscriptionUserInfo
{
    /// <summary>Bytes uploaded, when reported.</summary>
    public long? Upload { get; init; }

    /// <summary>Bytes downloaded, when reported.</summary>
    public long? Download { get; init; }

    /// <summary>Quota in bytes. <c>0</c> means unlimited.</summary>
    public long? Total { get; init; }

    /// <summary>Expiry timestamp. <c>null</c> when absent or reported as 0.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>True when the provider reported no expiry or an expiry of 0.</summary>
    public bool HasNoExpiry => ExpiresAt is null;

    /// <summary>True when the quota is absent or explicitly 0.</summary>
    public bool IsUnlimited => Total is null or 0;

    /// <summary>Bytes used so far, when at least one counter was reported.</summary>
    public long? Used => Upload is null && Download is null
        ? null
        : (Upload ?? 0) + (Download ?? 0);

    /// <summary>Fraction of the quota used, 0..1; <c>null</c> when not computable.</summary>
    public double? UsedFraction
    {
        get
        {
            if (IsUnlimited || Used is not { } used || Total is not { } total || total <= 0)
            {
                return null;
            }

            return Math.Clamp((double)used / total, 0.0, 1.0);
        }
    }

    public bool IsExpired(DateTimeOffset now) => ExpiresAt is { } expiry && expiry <= now;

    /// <summary>Days remaining until expiry, or <c>null</c> when there is no expiry.</summary>
    public int? DaysRemaining(DateTimeOffset now)
    {
        if (ExpiresAt is not { } expiry)
        {
            return null;
        }

        var remaining = expiry - now;
        return remaining <= TimeSpan.Zero ? 0 : (int)Math.Floor(remaining.TotalDays);
    }

    /// <summary>
    /// Parses the <c>subscription-userinfo</c> value.
    /// </summary>
    /// <remarks>
    /// Unknown keys are ignored rather than treated as an error: providers add fields
    /// over time and a client that hard-fails on a new key would break for everyone.
    /// A value that contains no recognizable key at all is rejected, because that
    /// indicates the header is not what we think it is.
    /// </remarks>
    public static bool TryParse(string? value, out SubscriptionUserInfo info, out string? failureCode)
    {
        info = new SubscriptionUserInfo();
        failureCode = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            failureCode = "empty";
            return false;
        }

        long? upload = null;
        long? download = null;
        long? total = null;
        DateTimeOffset? expires = null;
        var recognized = 0;

        // Both ';' (documented) and ',' (seen in the wild) are accepted as separators.
        foreach (var segment in value.Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = segment.Trim().Trim('"');
            if (trimmed.Length == 0)
            {
                continue;
            }

            var equals = trimmed.IndexOf('=');
            if (equals <= 0)
            {
                failureCode = "missing_equals";
                return false;
            }

            var key = trimmed[..equals].Trim().ToLowerInvariant();
            var rawValue = trimmed[(equals + 1)..].Trim().Trim('"');

            if (rawValue.Length == 0)
            {
                failureCode = "empty_value";
                return false;
            }

            // Values are non-negative. A negative counter is nonsense and is rejected
            // rather than clamped, so a broken panel is visible instead of silent.
            if (!TryParseNonNegativeNumber(rawValue, out var number))
            {
                failureCode = $"not_a_number:{key}";
                return false;
            }

            switch (key)
            {
                case "upload":
                    upload = number;
                    recognized++;
                    break;
                case "download":
                    download = number;
                    recognized++;
                    break;
                case "total":
                    total = number;
                    recognized++;
                    break;
                case "expire":
                    expires = ToExpiry(number);
                    recognized++;
                    break;
                default:
                    // Unknown key: ignore, do not fail.
                    break;
            }
        }

        if (recognized == 0)
        {
            failureCode = "no_recognized_keys";
            return false;
        }

        info = new SubscriptionUserInfo
        {
            Upload = upload,
            Download = download,
            Total = total,
            ExpiresAt = expires,
        };

        return true;
    }

    /// <summary>
    /// Converts the <c>expire</c> field to a timestamp. Both Unix seconds and
    /// Unix milliseconds appear in the wild; values that can only be milliseconds are
    /// detected by magnitude.
    /// </summary>
    private static DateTimeOffset? ToExpiry(long value)
    {
        if (value <= 0)
        {
            return null;
        }

        // A seconds value for any plausible date is far below 1e11 (year 5138).
        var seconds = value > 100_000_000_000 ? value / 1000 : value;

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(seconds);
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
    }

    private static bool TryParseNonNegativeNumber(string text, out long value)
    {
        value = 0;

        if (text.Length == 0)
        {
            return false;
        }

        // Integer form, by far the common case.
        if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed))
        {
            if (parsed < 0)
            {
                return false;
            }

            value = parsed;
            return true;
        }

        // Float form, emitted by some panels.
        if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var asDouble))
        {
            if (asDouble < 0 || double.IsNaN(asDouble) || double.IsInfinity(asDouble) || asDouble > long.MaxValue)
            {
                return false;
            }

            value = (long)Math.Round(asDouble);
            return true;
        }

        return false;
    }
}
