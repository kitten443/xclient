using System.Text;
using MyVpn.Core.Geo;

namespace MyVpn.Integration.Tests;

/// <summary>
/// Builds real geo data protobuf fixtures for the integration tests.
/// </summary>
/// <remarks>
/// The fixture format is the one Xray's <c>.dat</c> files use: a message whose repeated
/// field 1 holds entries, each with a printable code in its own field 1. The unknown
/// padding field keeps every entry above <see cref="GeoAssetValidator.MinimumPlausibleSizeBytes"/>
/// and simultaneously exercises the forward-compatibility path where unknown fields are
/// skipped rather than rejected. This mirrors the technique used by
/// <c>tests/MyVpn.Infrastructure.Tests/GeoDataManagerTests.cs</c>.
/// </remarks>
internal static class IntegrationGeoFixture
{
    public static byte[] BuildValidGeoAsset(int entryCount = 200, int padding = 40)
    {
        using var buffer = new MemoryStream();

        for (var i = 0; i < entryCount; i++)
        {
            WriteLengthDelimited(buffer, fieldNumber: 1, BuildEntry($"c{i}", padding));
        }

        return buffer.ToArray();
    }

    public static void WriteAsset(string directory, GeoAssetKind kind, byte[] content)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(Path.Combine(directory, kind.FileName()), content);
    }

    /// <summary>An HTML error page sized like a real asset: the captive-portal failure mode.</summary>
    public static byte[] BuildCorruptGeoAsset()
    {
        var html = "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>"
                   + new string('x', 6000)
                   + "</body></html>";

        return Encoding.UTF8.GetBytes(html);
    }

    private static byte[] BuildEntry(string code, int padding)
    {
        using var entry = new MemoryStream();

        // field 1, wire type 2: the code string.
        WriteLengthDelimited(entry, fieldNumber: 1, Encoding.ASCII.GetBytes(code));

        if (padding > 0)
        {
            // field 9, wire type 2: an unknown field that must be skipped.
            WriteLengthDelimited(entry, fieldNumber: 9, new byte[padding]);
        }

        return entry.ToArray();
    }

    private static void WriteLengthDelimited(Stream stream, int fieldNumber, byte[] payload)
    {
        WriteVarint(stream, (ulong)((fieldNumber << 3) | 2));
        WriteVarint(stream, (ulong)payload.Length);
        stream.Write(payload, 0, payload.Length);
    }

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80)
        {
            stream.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }

        stream.WriteByte((byte)value);
    }
}
