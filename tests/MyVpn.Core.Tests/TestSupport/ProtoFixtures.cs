using System.Text;

namespace MyVpn.Core.Tests;

/// <summary>
/// Hand-built protobuf wire-format fixtures for the geo asset validator.
/// Deliberately does not use Google.Protobuf: MyVpn.Core validates the wire
/// format itself, so the tests must produce bytes, not schema objects.
/// </summary>
internal static class ProtoFixtures
{
    public static byte[] Varint(ulong value)
    {
        var buffer = new List<byte>(10);
        do
        {
            var b = (byte)(value & 0x7F);
            value >>= 7;
            if (value != 0)
            {
                b |= 0x80;
            }

            buffer.Add(b);
        }
        while (value != 0);

        return buffer.ToArray();
    }

    public static byte[] Tag(int fieldNumber, int wireType) =>
        Varint((ulong)((fieldNumber << 3) | wireType));

    public static byte[] LengthDelimited(int fieldNumber, ReadOnlySpan<byte> payload)
    {
        var tag = Tag(fieldNumber, 2);
        var length = Varint((ulong)payload.Length);
        var result = new byte[tag.Length + length.Length + payload.Length];
        tag.CopyTo(result, 0);
        length.CopyTo(result, tag.Length);
        payload.CopyTo(result.AsSpan(tag.Length + length.Length));
        return result;
    }

    /// <summary>One geo entry sub-message with field 1 = printable ASCII code.</summary>
    public static byte[] Entry(string code) => LengthDelimited(1, Encoding.ASCII.GetBytes(code));

    /// <summary>An entry sub-message that carries no field-1 code at all.</summary>
    public static byte[] EntryWithoutCode() => LengthDelimited(2, "not-a-code"u8);

    public static byte[] Concat(params byte[][] parts)
    {
        var total = parts.Sum(p => p.Length);
        var result = new byte[total];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }

        return result;
    }

    /// <summary>
    /// Builds a top-level message whose repeated field 1 holds one entry per code.
    /// When <paramref name="paddingFieldBytes"/> is positive an unknown top-level
    /// field 2 (length-delimited) is appended to push the file past the minimum size.
    /// </summary>
    public static byte[] GeoAsset(IEnumerable<string> codes, int paddingFieldBytes = 0)
    {
        using var stream = new MemoryStream();
        foreach (var code in codes)
        {
            // Each geo entry is a repeated top-level field 1 holding the entry message.
            var entry = LengthDelimited(1, Entry(code));
            stream.Write(entry, 0, entry.Length);
        }

        if (paddingFieldBytes > 0)
        {
            var padding = LengthDelimited(2, new byte[paddingFieldBytes]);
            stream.Write(padding, 0, padding.Length);
        }

        return stream.ToArray();
    }

    public static byte[] HtmlErrorPage(int repetitions = 400) =>
        Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("<html><body>error</body></html>\n", repetitions)));
}
