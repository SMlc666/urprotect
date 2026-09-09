using System.Buffers.Binary;
using System.Text;

namespace UrProtect.Core.Binary;

public sealed class BoundedReader
{
    private readonly ReadOnlyMemory<byte> source;

    public BoundedReader(ReadOnlyMemory<byte> source)
    {
        this.source = source;
    }

    public int Length => source.Length;

    public ReadOnlyMemory<byte> Source => source;

    public bool TryReadByte(ulong offset, out byte value)
    {
        value = default;
        if (!TryGetIndex(offset, sizeof(byte), out var index))
        {
            return false;
        }

        value = source.Span[index];
        return true;
    }

    public bool TryReadUInt16(ulong offset, out ushort value)
    {
        value = default;
        if (!TryGetIndex(offset, sizeof(ushort), out var index))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt16LittleEndian(source.Span[index..]);
        return true;
    }

    public bool TryReadUInt32(ulong offset, out uint value)
    {
        value = default;
        if (!TryGetIndex(offset, sizeof(uint), out var index))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt32LittleEndian(source.Span[index..]);
        return true;
    }

    public bool TryReadUInt64(ulong offset, out ulong value)
    {
        value = default;
        if (!TryGetIndex(offset, sizeof(ulong), out var index))
        {
            return false;
        }

        value = BinaryPrimitives.ReadUInt64LittleEndian(source.Span[index..]);
        return true;
    }

    public bool TryReadInt64(ulong offset, out long value)
    {
        value = default;
        if (!TryReadUInt64(offset, out var raw))
        {
            return false;
        }

        value = unchecked((long)raw);
        return true;
    }

    public bool TryReadInt32(ulong offset, out int value)
    {
        value = default;
        if (!TryReadUInt32(offset, out var raw))
        {
            return false;
        }

        value = unchecked((int)raw);
        return true;
    }

    public bool TrySlice(ulong offset, ulong length, out ReadOnlyMemory<byte> slice)
    {
        slice = default;
        if (length > int.MaxValue || !TryGetIndex(offset, length, out var index))
        {
            return false;
        }

        slice = source.Slice(index, (int)length);
        return true;
    }

    public bool TryReadUtf8Z(ulong offset, ulong maxLength, out string value)
    {
        value = string.Empty;
        if (!TrySlice(offset, maxLength, out var slice))
        {
            return false;
        }

        var span = slice.Span;
        var terminator = span.IndexOf((byte)0);
        if (terminator < 0)
        {
            return false;
        }

        value = Encoding.UTF8.GetString(span[..terminator]);
        return true;
    }

    public bool Contains(ulong offset, ulong length) =>
        length <= int.MaxValue && TryGetIndex(offset, length, out _);

    private bool TryGetIndex(ulong offset, ulong length, out int index)
    {
        index = default;
        if (offset > int.MaxValue || length > int.MaxValue)
        {
            return false;
        }

        var end = offset + length;
        if (end < offset || end > (ulong)source.Length)
        {
            return false;
        }

        index = (int)offset;
        return true;
    }
}
