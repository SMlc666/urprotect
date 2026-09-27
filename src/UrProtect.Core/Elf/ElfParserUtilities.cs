using System.Text;
using UrProtect.Core.Binary;

namespace UrProtect.Core.Elf;

internal static class ElfParserUtilities
{
    internal static bool TryResolveVirtualRange(
        BoundedReader reader,
        LoadMap loadMap,
        ulong virtualAddress,
        ulong size,
        out ulong fileOffset)
    {
        fileOffset = default;
        if (!loadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(virtualAddress),
                size,
                out var mappedOffset)
            || !reader.Contains(mappedOffset.Value, size))
        {
            return false;
        }

        fileOffset = mappedOffset.Value;
        return true;
    }

    internal static bool TryGetDynamicValue(
        IReadOnlyList<DynamicEntry> entries,
        ulong tag,
        out ulong value)
    {
        for (var index = 0; index < entries.Count; index++)
        {
            var entry = entries[index];
            if (entry.Tag == tag)
            {
                value = entry.Value;
                return true;
            }
        }

        value = default;
        return false;
    }

    internal static bool TryReadString(
        ReadOnlyMemory<byte> table,
        ulong offset,
        out string value)
    {
        value = string.Empty;
        if (offset >= (ulong)table.Length)
        {
            return false;
        }

        var bytes = table.Span[(int)offset..];
        var terminator = bytes.IndexOf((byte)0);
        if (terminator < 0)
        {
            return false;
        }

        value = Encoding.UTF8.GetString(bytes[..terminator]);
        return true;
    }

    internal static bool TryTableRange(
        ulong offset,
        ulong entrySize,
        ulong count,
        int sourceLength,
        out ulong size)
    {
        size = 0;
        if (!TryMultiply(entrySize, count, out size))
        {
            return false;
        }

        return TryAdd(offset, size, out var end) && end <= (ulong)sourceLength;
    }

    internal static bool TryElementOffset(
        ulong baseOffset,
        ulong entrySize,
        ulong index,
        out ulong offset)
    {
        offset = default;
        return TryMultiply(entrySize, index, out var delta)
            && TryAdd(baseOffset, delta, out offset)
            && offset <= int.MaxValue;
    }

    internal static bool TryAlign4(ulong value, out ulong aligned)
    {
        if (value > ulong.MaxValue - 3)
        {
            aligned = default;
            return false;
        }

        aligned = (value + 3) & ~3UL;
        return true;
    }

    internal static bool TryAdd(ulong left, ulong right, out ulong result)
    {
        result = left + right;
        return result >= left;
    }

    internal static bool TrySubtract(ulong left, ulong right, out ulong result)
    {
        if (left < right)
        {
            result = default;
            return false;
        }

        result = left - right;
        return true;
    }

    internal static bool TryMultiply(ulong left, ulong right, out ulong result)
    {
        if (left != 0 && right > ulong.MaxValue / left)
        {
            result = default;
            return false;
        }

        result = left * right;
        return true;
    }

    internal static bool IsPowerOfTwo(ulong value) => (value & (value - 1)) == 0;
}
