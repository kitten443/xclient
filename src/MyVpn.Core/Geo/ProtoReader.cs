namespace MyVpn.Core.Geo;

/// <summary>
/// Minimal, allocation-light protobuf wire-format reader.
/// </summary>
/// <remarks>
/// <para>
/// MyVpn validates <c>geoip.dat</c> / <c>geosite.dat</c> structurally instead of
/// merely checking that the file exists and is non-empty. That requires walking the
/// protobuf wire format, and pulling in the full <c>Google.Protobuf</c> runtime plus
/// generated schema types just to count entries would add a dependency and a large
/// attack surface for a check that only needs the wire format.
/// </para>
/// <para>
/// This reader therefore decodes only tags, varints and length-delimited fields, and
/// never materializes objects. It is a <see langword="ref struct"/> so it can walk a
/// stack-allocated or pooled span with zero heap allocation.
/// </para>
/// </remarks>
public ref struct ProtoReader
{
    private readonly ReadOnlySpan<byte> _buffer;
    private int _position;

    public ProtoReader(ReadOnlySpan<byte> buffer)
    {
        _buffer = buffer;
        _position = 0;
    }

    /// <summary>True when the whole buffer has been consumed.</summary>
    public bool End => _position >= _buffer.Length;

    /// <summary>Current byte offset; used to build precise diagnostics.</summary>
    public int Position => _position;

    public int Remaining => _buffer.Length - _position;

    /// <summary>Reads a base-128 varint.</summary>
    public bool TryReadVarint(out ulong value)
    {
        value = 0;
        var shift = 0;

        // A protobuf varint is at most 10 bytes for a 64-bit value.
        for (var i = 0; i < 10; i++)
        {
            if (_position >= _buffer.Length)
            {
                return false;
            }

            var b = _buffer[_position++];
            value |= (ulong)(b & 0x7F) << shift;

            if ((b & 0x80) == 0)
            {
                return true;
            }

            shift += 7;
        }

        // More than 10 continuation bytes: malformed.
        return false;
    }

    /// <summary>Reads a field tag into its field number and wire type.</summary>
    public bool TryReadTag(out int fieldNumber, out int wireType)
    {
        fieldNumber = 0;
        wireType = 0;

        if (!TryReadVarint(out var tag))
        {
            return false;
        }

        wireType = (int)(tag & 0x7);
        fieldNumber = (int)(tag >> 3);

        // Field number 0 is illegal; wire types 6 and 7 do not exist.
        return fieldNumber >= 1 && wireType <= 5;
    }

    /// <summary>Reads a length-delimited field payload.</summary>
    public bool TryReadLengthDelimited(out ReadOnlySpan<byte> value)
    {
        value = default;

        if (!TryReadVarint(out var length))
        {
            return false;
        }

        // A length that does not fit in an int, or that runs past the buffer, means
        // the file is truncated or is not protobuf at all.
        if (length > int.MaxValue || length > (ulong)Remaining)
        {
            return false;
        }

        var len = (int)length;
        value = _buffer.Slice(_position, len);
        _position += len;
        return true;
    }

    /// <summary>Skips a field of the given wire type without interpreting it.</summary>
    /// <remarks>
    /// Unknown fields are skipped rather than rejected so that a newer geo data
    /// release, which may add fields, still validates. This is forward compatibility,
    /// not laxity: a malformed skip still fails.
    /// </remarks>
    public bool TrySkipField(int wireType)
    {
        switch (wireType)
        {
            case 0: // varint
                return TryReadVarint(out _);
            case 1: // 64-bit
                return Advance(8);
            case 2: // length-delimited
                return TryReadLengthDelimited(out _);
            case 3: // start group — deprecated; treat as malformed
            case 4: // end group
                return false;
            case 5: // 32-bit
                return Advance(4);
            default:
                return false;
        }
    }

    private bool Advance(int count)
    {
        if (count < 0 || count > Remaining)
        {
            return false;
        }

        _position += count;
        return true;
    }
}
