namespace UrProtect.Core.Elf;

public readonly record struct LoadSegment(
    ulong FileOffset,
    ulong VirtualAddress,
    ulong FileSize,
    ulong MemorySize,
    uint Flags,
    ulong Alignment)
{
    public bool IsExecutable => (Flags & ElfConstants.PfX) != 0;

    public bool ContainsFileOffset(ulong offset, ulong size = 1)
    {
        return offset >= FileOffset
            && size <= FileSize
            && offset - FileOffset <= FileSize - size;
    }

    public bool ContainsVirtualAddress(ulong address, ulong size = 1)
    {
        return address >= VirtualAddress
            && size <= FileSize
            && address - VirtualAddress <= FileSize - size;
    }
}

public sealed class LoadMap
{
    private readonly IReadOnlyList<LoadSegment> segments;

    private LoadMap(IReadOnlyList<LoadSegment> segments)
    {
        this.segments = segments;
    }

    public IReadOnlyList<LoadSegment> Segments => segments;

    public static LoadMap Create(IEnumerable<ProgramHeader> programHeaders)
    {
        ArgumentNullException.ThrowIfNull(programHeaders);
        var mappings = new List<LoadSegment>();
        foreach (var header in programHeaders)
        {
            if (!header.IsLoadable)
            {
                continue;
            }

            mappings.Add(new LoadSegment(
                header.Offset,
                header.VirtualAddress,
                header.FileSize,
                header.MemorySize,
                header.Flags,
                header.Alignment));
        }

        return new LoadMap(mappings);
    }

    public bool TryFileOffsetToVirtualAddress(ulong fileOffset, out ulong virtualAddress)
    {
        return TryFileOffsetToVirtualAddress(fileOffset, 1, out virtualAddress);
    }

    public bool TryFileOffsetToVirtualAddress(
        ulong fileOffset,
        ulong size,
        out ulong virtualAddress)
    {
        foreach (var segment in segments)
        {
            if (!segment.ContainsFileOffset(fileOffset, size))
            {
                continue;
            }

            var delta = fileOffset - segment.FileOffset;
            if (segment.VirtualAddress > ulong.MaxValue - delta)
            {
                break;
            }

            virtualAddress = segment.VirtualAddress + delta;
            return true;
        }

        virtualAddress = default;
        return false;
    }

    public bool TryVirtualAddressToFileOffset(ulong virtualAddress, out ulong fileOffset)
    {
        return TryVirtualAddressToFileOffset(virtualAddress, 1, out fileOffset);
    }

    public bool TryVirtualAddressToFileOffset(
        ulong virtualAddress,
        ulong size,
        out ulong fileOffset)
    {
        foreach (var segment in segments)
        {
            if (!segment.ContainsVirtualAddress(virtualAddress, size))
            {
                continue;
            }

            var delta = virtualAddress - segment.VirtualAddress;
            if (segment.FileOffset > ulong.MaxValue - delta)
            {
                break;
            }

            fileOffset = segment.FileOffset + delta;
            return true;
        }

        fileOffset = default;
        return false;
    }

    public static bool TryRuntimeAddressToVirtualAddress(ulong runtimeAddress, ulong loadBias, out ulong virtualAddress)
    {
        if (runtimeAddress < loadBias)
        {
            virtualAddress = default;
            return false;
        }

        virtualAddress = runtimeAddress - loadBias;
        return true;
    }

    public static bool TryVirtualAddressToRuntimeAddress(ulong virtualAddress, ulong loadBias, out ulong runtimeAddress)
    {
        runtimeAddress = virtualAddress + loadBias;
        return runtimeAddress >= virtualAddress;
    }
}
