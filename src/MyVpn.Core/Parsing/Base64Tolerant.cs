using System.Text;

namespace MyVpn.Core.Parsing;

/// <summary>
/// Tolerant Base64 decoding for subscription payloads and share links.
/// </summary>
/// <remarks>
/// There is no single Base64 dialect in the wild. Subscription bodies are frequently
/// standard Base64 with padding, but <c>vmess://</c> payloads and many panels emit
/// URL-safe Base64 with the padding stripped. Rather than guess one dialect, the
/// decoder accepts both alphabets and both padding conventions, and rejects only
/// genuinely malformed input.
/// </remarks>
public static class Base64Tolerant
{
    /// <summary>
    /// Decodes standard or URL-safe Base64, with or without padding.
    /// </summary>
    public static bool TryDecode(string? input, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();

        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var normalized = Normalize(input);
        if (normalized is null)
        {
            return false;
        }

        try
        {
            bytes = Convert.FromBase64String(normalized);
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>Decodes Base64 into UTF-8 text.</summary>
    public static bool TryDecodeToString(string? input, out string text)
    {
        text = string.Empty;

        if (!TryDecode(input, out var bytes))
        {
            return false;
        }

        try
        {
            // Strip a UTF-8 BOM: some panels prepend one to the subscription body.
            var span = bytes.AsSpan();
            if (span.Length >= 3 && span[0] == 0xEF && span[1] == 0xBB && span[2] == 0xBF)
            {
                span = span[3..];
            }

            text = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
                .GetString(span);
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    /// <summary>Encodes to unpadded URL-safe Base64.</summary>
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string EncodeString(string text) => Encode(Encoding.UTF8.GetBytes(text));

    /// <summary>
    /// True when the text looks like Base64 rather than a list of share links. Used to
    /// decide whether a subscription body needs decoding before it is split into lines.
    /// </summary>
    public static bool LooksLikeBase64(string? input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var trimmed = input.Trim();
        if (trimmed.Length < 16)
        {
            return false;
        }

        // A body containing a scheme separator is already plain text.
        if (trimmed.Contains("://", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var c in trimmed)
        {
            if (char.IsWhiteSpace(c))
            {
                // Multi-line input is line-separated plain text unless every line is b64.
                return false;
            }

            if (!(char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_' or '='))
            {
                return false;
            }
        }

        return trimmed.Length % 4 != 1;
    }

    private static string? Normalize(string input)
    {
        // Remove all whitespace and newlines that appear inside wrapped Base64.
        var sb = new StringBuilder(input.Length);

        foreach (var c in input)
        {
            if (char.IsWhiteSpace(c))
            {
                continue;
            }

            sb.Append(c switch
            {
                '-' => '+',
                '_' => '/',
                _ => c,
            });
        }

        var value = sb.ToString();
        if (value.Length == 0)
        {
            return null;
        }

        var remainder = value.Length % 4;
        return remainder switch
        {
            0 => value,
            2 => value + "==",
            3 => value + "=",
            // A remainder of 1 can never be valid Base64.
            _ => null,
        };
    }
}
