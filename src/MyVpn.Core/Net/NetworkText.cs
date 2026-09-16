using System.Net;

namespace MyVpn.Core.Net;

/// <summary>Text validation for hosts, domains and IP literals used by settings and rules.</summary>
public static class NetworkText
{
    /// <summary>
    /// Validates an IPv4/IPv6 address or CIDR block.
    /// </summary>
    public static bool IsIpOrCidr(string? text) => CidrBlock.TryParse(text, out _);

    /// <summary>Validates a bare IP address with no prefix.</summary>
    public static bool IsIpAddress(string? text) =>
        !string.IsNullOrWhiteSpace(text) && IPAddress.TryParse(text.Trim(), out _);

    /// <summary>
    /// Validates a routing domain pattern, accepting the forms Xray itself accepts:
    /// <c>example.com</c>, <c>full:example.com</c>, <c>domain:example.com</c>,
    /// <c>regexp:^.*\.example\.com$</c>, <c>keyword:ads</c> and <c>geosite:cn</c>.
    /// </summary>
    public static bool IsValidDomainPattern(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var value = text.Trim();
        if (value.Length > 255)
        {
            return false;
        }

        var colon = value.IndexOf(':');
        if (colon > 0)
        {
            var prefix = value[..colon];
            var rest = value[(colon + 1)..];

            switch (prefix)
            {
                case "full":
                case "domain":
                    return IsValidHostName(rest);
                case "keyword":
                    return rest.Length is > 0 and <= 128;
                case "regexp":
                    return IsValidRegex(rest);
                case "geosite":
                    return rest.Length is > 0 and <= 64 && rest.All(IsGeoCodeChar);
                case "ext":
                    // ext:file:tag — resolved against the asset directory. Refuse path
                    // separators here; the caller validates the file name separately.
                    return rest.Length is > 0 and <= 200
                           && !rest.Contains('/')
                           && !rest.Contains('\\')
                           && !rest.Contains("..", StringComparison.Ordinal);
                default:
                    return false;
            }
        }

        return IsValidHostName(value);
    }

    /// <summary>Validates a DNS host name or a single-label name.</summary>
    public static bool IsValidHostName(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > 253)
        {
            return false;
        }

        var value = text.Trim().TrimEnd('.');

        // A wildcard prefix is accepted as a domain suffix match.
        if (value.StartsWith("*.", StringComparison.Ordinal))
        {
            value = value[2..];
        }

        if (value.Length == 0)
        {
            return false;
        }

        foreach (var label in value.Split('.'))
        {
            if (label.Length is 0 or > 63)
            {
                return false;
            }

            foreach (var c in label)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_'))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// Validates a regular expression without compiling it into the running process's
    /// regex cache unnecessarily. Malformed patterns must be rejected at input time.
    /// </summary>
    public static bool IsValidRegex(string pattern)
    {
        if (string.IsNullOrEmpty(pattern) || pattern.Length > 512)
        {
            return false;
        }

        try
        {
            _ = new System.Text.RegularExpressions.Regex(
                pattern,
                System.Text.RegularExpressions.RegexOptions.None,
                TimeSpan.FromMilliseconds(200));
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsGeoCodeChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '!' or '+' or '.';
}
