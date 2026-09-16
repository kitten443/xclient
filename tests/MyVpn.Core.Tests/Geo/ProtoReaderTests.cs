using MyVpn.Core.Geo;
using Shouldly;

namespace MyVpn.Core.Tests;

public sealed class ProtoReaderTests
{
    [Fact]
    public void Reads_a_single_byte_varint()
    {
        var reader = new ProtoReader(new byte[] { 0x2A, 0x07 });

        reader.TryReadVarint(out var first).ShouldBeTrue();
        first.ShouldBe(42UL);

        reader.TryReadVarint(out var second).ShouldBeTrue();
        second.ShouldBe(7UL);

        reader.End.ShouldBeTrue();
    }

    [Fact]
    public void Reads_a_multi_byte_varint()
    {
        var reader = new ProtoReader(new byte[] { 0xAC, 0x02 });

        reader.TryReadVarint(out var value).ShouldBeTrue();

        value.ShouldBe(300UL);
    }

    [Fact]
    public void Reads_the_largest_ten_byte_varint()
    {
        // 0xFFFFFFFFFFFFFFFF => nine 0xFF continuation bytes then 0x01.
        var bytes = new byte[10];
        for (var i = 0; i < 9; i++)
        {
            bytes[i] = 0xFF;
        }

        bytes[9] = 0x01;

        var reader = new ProtoReader(bytes);
        reader.TryReadVarint(out var value).ShouldBeTrue();

        value.ShouldBe(ulong.MaxValue);
    }

    [Fact]
    public void Rejects_a_varint_that_never_terminates()
    {
        var bytes = new byte[10];
        Array.Fill(bytes, (byte)0x80);

        var reader = new ProtoReader(bytes);
        reader.TryReadVarint(out _).ShouldBeFalse();
    }

    [Fact]
    public void Rejects_a_varint_longer_than_ten_bytes()
    {
        var bytes = new byte[11];
        Array.Fill(bytes, (byte)0x80);
        bytes[10] = 0x01;

        var reader = new ProtoReader(bytes);
        reader.TryReadVarint(out _).ShouldBeFalse();
    }

    [Fact]
    public void Rejects_a_varint_when_the_buffer_is_empty()
    {
        var reader = new ProtoReader(ReadOnlySpan<byte>.Empty);

        reader.TryReadVarint(out _).ShouldBeFalse();
        reader.End.ShouldBeTrue();
        reader.Remaining.ShouldBe(0);
    }

    [Fact]
    public void Reads_a_field_tag()
    {
        // field 1, wire type 2 => 0x0A
        var reader = new ProtoReader(new byte[] { 0x0A });

        reader.TryReadTag(out var field, out var wireType).ShouldBeTrue();

        field.ShouldBe(1);
        wireType.ShouldBe(2);
    }

    [Fact]
    public void Reads_a_higher_field_number_tag()
    {
        // field 16, wire type 0 => (16 << 3) | 0 = 128 => 0x80 0x01
        var reader = new ProtoReader(new byte[] { 0x80, 0x01 });

        reader.TryReadTag(out var field, out var wireType).ShouldBeTrue();

        field.ShouldBe(16);
        wireType.ShouldBe(0);
    }

    [Fact]
    public void Rejects_field_number_zero()
    {
        foreach (var wireType in new[] { 0, 1, 2, 5 })
        {
            var reader = new ProtoReader(new byte[] { (byte)wireType });
            reader.TryReadTag(out _, out _).ShouldBeFalse($"wire type {wireType} with field 0");
        }
    }

    [Fact]
    public void Rejects_non_existent_wire_types()
    {
        // field 1 with wire type 6 => (1 << 3) | 6 = 14; wire type 7 => 15.
        foreach (var tag in new byte[] { 0x0E, 0x0F })
        {
            var reader = new ProtoReader(new byte[] { tag });
            reader.TryReadTag(out _, out _).ShouldBeFalse();
        }
    }

    [Fact]
    public void Reads_a_length_delimited_field()
    {
        var reader = new ProtoReader(new byte[] { 0x03, (byte)'a', (byte)'b', (byte)'c', 0xFF });

        reader.TryReadLengthDelimited(out var value).ShouldBeTrue();

        value.ToArray().ShouldBe(new byte[] { (byte)'a', (byte)'b', (byte)'c' });
        reader.Remaining.ShouldBe(1);
        reader.Position.ShouldBe(4);
    }

    [Fact]
    public void Rejects_a_length_that_runs_past_the_end()
    {
        var reader = new ProtoReader(new byte[] { 0x05, 0x01, 0x02 });

        reader.TryReadLengthDelimited(out _).ShouldBeFalse();
    }

    [Fact]
    public void Rejects_a_length_larger_than_an_int()
    {
        var length = ProtoFixtures.Varint((ulong)int.MaxValue + 1);
        var bytes = length.Concat(new byte[] { 0x01 }).ToArray();

        var reader = new ProtoReader(bytes);
        reader.TryReadLengthDelimited(out _).ShouldBeFalse();
    }

    [Fact]
    public void Rejects_a_length_delimited_field_with_no_length_byte()
    {
        var reader = new ProtoReader(ReadOnlySpan<byte>.Empty);

        reader.TryReadLengthDelimited(out _).ShouldBeFalse();
    }

    [Fact]
    public void Accepts_a_zero_length_field()
    {
        var reader = new ProtoReader(new byte[] { 0x00 });

        reader.TryReadLengthDelimited(out var value).ShouldBeTrue();

        value.Length.ShouldBe(0);
    }

    [Fact]
    public void Skips_a_varint_field()
    {
        var reader = new ProtoReader(new byte[] { 0x96, 0x01, 0x07 });

        reader.TrySkipField(0).ShouldBeTrue();

        reader.Position.ShouldBe(2);
        reader.Remaining.ShouldBe(1);
    }

    [Fact]
    public void Skips_a_sixty_four_bit_field()
    {
        var reader = new ProtoReader(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 });

        reader.TrySkipField(1).ShouldBeTrue();

        reader.Position.ShouldBe(8);
        reader.Remaining.ShouldBe(1);
    }

    [Fact]
    public void Skips_a_length_delimited_field()
    {
        var reader = new ProtoReader(new byte[] { 0x02, 0xAA, 0xBB, 0xCC });

        reader.TrySkipField(2).ShouldBeTrue();

        reader.Position.ShouldBe(3);
    }

    [Fact]
    public void Skips_a_thirty_two_bit_field()
    {
        var reader = new ProtoReader(new byte[] { 1, 2, 3, 4, 5 });

        reader.TrySkipField(5).ShouldBeTrue();

        reader.Position.ShouldBe(4);
        reader.Remaining.ShouldBe(1);
    }

    [Fact]
    public void Rejects_group_wire_types()
    {
        var startGroup = new ProtoReader(new byte[] { 0x01 });
        startGroup.TrySkipField(3).ShouldBeFalse();

        var endGroup = new ProtoReader(new byte[] { 0x01 });
        endGroup.TrySkipField(4).ShouldBeFalse();
    }

    [Fact]
    public void Rejects_an_unknown_skip_wire_type()
    {
        var reader = new ProtoReader(new byte[] { 0x01 });

        reader.TrySkipField(6).ShouldBeFalse();
        reader.TrySkipField(-1).ShouldBeFalse();
    }

    [Fact]
    public void A_skip_that_runs_past_the_end_fails()
    {
        var fixed64 = new ProtoReader(new byte[] { 1, 2, 3 });
        fixed64.TrySkipField(1).ShouldBeFalse();

        var fixed32 = new ProtoReader(new byte[] { 1, 2 });
        fixed32.TrySkipField(5).ShouldBeFalse();
    }

    [Fact]
    public void Position_remaining_and_end_track_consumption()
    {
        var reader = new ProtoReader(new byte[] { 0x0A, 0x02, 0xAA, 0xBB });

        reader.Position.ShouldBe(0);
        reader.Remaining.ShouldBe(4);
        reader.End.ShouldBeFalse();

        reader.TryReadTag(out _, out _).ShouldBeTrue();
        reader.TryReadLengthDelimited(out var value).ShouldBeTrue();

        value.Length.ShouldBe(2);
        reader.Position.ShouldBe(4);
        reader.Remaining.ShouldBe(0);
        reader.End.ShouldBeTrue();
    }
}
