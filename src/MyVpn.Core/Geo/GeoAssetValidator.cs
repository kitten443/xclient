using System.Text;

namespace MyVpn.Core.Geo;

/// <summary>Outcome of a structural validation of a geo data file.</summary>
public sealed record GeoAssetValidationResult(
    bool IsValid,
    int EntryCount,
    IReadOnlyList<string> SampleCodes,
    string? FailureCode,
    string? FailureDetail)
{
    /// <summary>True when at least one entry was decoded.</summary>
    public bool HasEntries => EntryCount > 0;

    public static GeoAssetValidationResult Valid(int entryCount, IReadOnlyList<string> sampleCodes) =>
        new(true, entryCount, sampleCodes, null, null);

    public static GeoAssetValidationResult Invalid(string failureCode, string failureDetail) =>
        new(false, 0, Array.Empty<string>(), failureCode, failureDetail);
}

/// <summary>
/// Structurally validates <c>geoip.dat</c> and <c>geosite.dat</c>.
/// </summary>
/// <remarks>
/// <para><b>Why this exists.</b> The failure class behind v2rayN issue #9765 is that a
/// geo data file can be <i>present</i> yet unusable: truncated by an interrupted
/// download, replaced by an HTML/JSON error page from a captive portal or a
/// misconfigured mirror, zero-filled by a failed disk write, or simply the wrong
/// file. An existence check — and even a "size &gt; 0" check — passes in every one of
/// those cases and the user then sees an opaque Xray asset error.</para>
/// <para><b>What it checks.</b> The file must be a protobuf message whose repeated
/// field 1 is a set of sub-messages, each carrying a printable ASCII code in field 1.
/// That is the shared shape of <c>GeoIPList</c> and <c>GeoSiteList</c>. The check is
/// deliberately structural rather than schema-exact: it will not reject a future
/// release that adds fields, but it reliably rejects truncation, wrong-file and
/// garbage content.</para>
/// <para>Pure function over bytes: no file system, no dependencies, fully unit
/// testable. File access lives in the infrastructure layer.</para>
/// </remarks>
public static class GeoAssetValidator
{
    /// <summary>
    /// Smallest file size that could plausibly be a valid asset. Guards against
    /// validating a handful of bytes as if it were a real database.
    /// </summary>
    public const long MinimumPlausibleSizeBytes = 4096;

    /// <summary>Upper bound on entries inspected, so a hostile file cannot burn CPU.</summary>
    private const int MaxEntriesInspected = 200_000;

    /// <summary>How many distinct codes to retain for display in diagnostics.</summary>
    private const int MaxSampleCodes = 16;

    /// <summary>Geo codes are short identifiers such as <c>cn</c> or <c>category-ads-all</c>.</summary>
    private const int MaxCodeLength = 64;

    /// <summary>Validates a size without reading the file.</summary>
    public static bool HasPlausibleSize(long sizeBytes) => sizeBytes >= MinimumPlausibleSizeBytes;

    /// <summary>
    /// Validates the content of a geo data file.
    /// </summary>
    /// <param name="kind">Which asset this is; affects only diagnostics wording.</param>
    /// <param name="content">The full file content.</param>
    public static GeoAssetValidationResult Validate(GeoAssetKind kind, ReadOnlySpan<byte> content)
    {
        if (content.Length == 0)
        {
            return GeoAssetValidationResult.Invalid(
                failureCode: "empty",
                failureDetail: $"{kind.FileName()} is empty (0 bytes).");
        }

        if (content.Length < MinimumPlausibleSizeBytes)
        {
            return GeoAssetValidationResult.Invalid(
                failureCode: "too_small",
                failureDetail: $"{kind.FileName()} is {content.Length} bytes, below the {MinimumPlausibleSizeBytes}-byte minimum.");
        }

        var reader = new ProtoReader(content);
        var entries = 0;
        var unknownTopLevelFields = 0;
        var sampleCodes = new List<string>(MaxSampleCodes);

        while (!reader.End)
        {
            if (entries >= MaxEntriesInspected)
            {
                // Extremely large but structurally sound: accept, reporting the cap.
                break;
            }

            if (!reader.TryReadTag(out var fieldNumber, out var wireType))
            {
                return GeoAssetValidationResult.Invalid(
                    "truncated_tag",
                    $"{kind.FileName()} is truncated or not protobuf (bad tag at offset {reader.Position}).");
            }

            if (fieldNumber != 1)
            {
                unknownTopLevelFields++;
                if (!reader.TrySkipField(wireType))
                {
                    return GeoAssetValidationResult.Invalid(
                        "malformed_field",
                        $"{kind.FileName()} has a malformed field {fieldNumber} at offset {reader.Position}.");
                }

                continue;
            }

            if (wireType != 2)
            {
                return GeoAssetValidationResult.Invalid(
                    "wrong_wire_type",
                    $"{kind.FileName()} field 1 has wire type {wireType}, expected a length-delimited entry message.");
            }

            if (!reader.TryReadLengthDelimited(out var entry))
            {
                return GeoAssetValidationResult.Invalid(
                    "truncated_entry",
                    $"{kind.FileName()} declares an entry that runs past the end of the file at offset {reader.Position}. The file is most likely a truncated download.");
            }

            if (!TryExtractCode(entry, out var code))
            {
                return GeoAssetValidationResult.Invalid(
                    "malformed_entry",
                    $"{kind.FileName()} entry #{entries + 1} is malformed (cannot read its code field).");
            }

            if (code is null)
            {
                return GeoAssetValidationResult.Invalid(
                    "entry_without_code",
                    $"{kind.FileName()} entry #{entries + 1} has no printable code. The file is probably not geo data at all (an HTML or JSON error page saved as .dat has this shape).");
            }

            if (sampleCodes.Count < MaxSampleCodes && !sampleCodes.Contains(code, StringComparer.Ordinal))
            {
                sampleCodes.Add(code);
            }

            entries++;
        }

        if (entries == 0)
        {
            var hint = unknownTopLevelFields > 0
                ? $" It contains {unknownTopLevelFields} top-level field(s) but no entries; it is likely the wrong kind of protobuf message."
                : string.Empty;

            return GeoAssetValidationResult.Invalid(
                "no_entries",
                $"{kind.FileName()} contains no geo entries.{hint}");
        }

        return GeoAssetValidationResult.Valid(entries, sampleCodes);
    }

    /// <summary>
    /// Extracts the printable code from an entry sub-message.
    /// </summary>
    /// <returns>
    /// <see langword="false"/> when the sub-message is structurally malformed;
    /// <see langword="true"/> with <paramref name="code"/> <see langword="null"/> when it
    /// is well-formed but carries no usable code.
    /// </returns>
    private static bool TryExtractCode(ReadOnlySpan<byte> entry, out string? code)
    {
        code = null;
        var reader = new ProtoReader(entry);

        while (!reader.End)
        {
            if (!reader.TryReadTag(out var fieldNumber, out var wireType))
            {
                return false;
            }

            if (fieldNumber == 1 && wireType == 2)
            {
                if (!reader.TryReadLengthDelimited(out var value))
                {
                    return false;
                }

                if (code is null && TryDecodeCode(value, out var decoded))
                {
                    code = decoded;
                }

                continue;
            }

            if (!reader.TrySkipField(wireType))
            {
                return false;
            }
        }

        return true;
    }

    private static bool TryDecodeCode(ReadOnlySpan<byte> value, out string code)
    {
        code = string.Empty;

        if (value.Length is 0 or > MaxCodeLength)
        {
            return false;
        }

        // Geo codes are printable ASCII (ISO-3166 alpha-2, "private", "category-ads-all",
        // "geolocation-!cn", ...). Anything else means this is not the field we think it is.
        foreach (var b in value)
        {
            if (b is < 0x20 or > 0x7E)
            {
                return false;
            }
        }

        code = Encoding.ASCII.GetString(value);
        return true;
    }
}
