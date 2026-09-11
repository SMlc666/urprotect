using UrProtect.Core.Binary;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class BinaryPropertyTests
{
    [Fact]
    [Trait("Category", "Binary")]
    public void BoundedReaderRangeOperationsNeverThrowForRandomRanges()
    {
        var reader = new BoundedReader(new byte[64]);
        var random = new Random(0xB14A7);

        for (var iteration = 0; iteration < 10_000; iteration++)
        {
            var offset = random.Next(0, 129);
            var length = random.Next(0, 129);
            var expected = offset <= 64 && length <= 64 - offset;

            var exception = Record.Exception(() =>
            {
                Assert.Equal(expected, reader.Contains((ulong)offset, (ulong)length));
                Assert.Equal(expected, reader.TrySlice((ulong)offset, (ulong)length, out _));
            });

            Assert.Null(exception);
        }
    }

    [Fact]
    [Trait("Category", "Binary")]
    public void FileRangeRejectsOverflowAndPreservesEmptyRangeRules()
    {
        var overflowing = new FileRange(ulong.MaxValue - 3, 8);

        Assert.False(overflowing.TryGetEnd(out _));
        Assert.False(overflowing.Contains(ulong.MaxValue - 2));

        var empty = new FileRange(12, 0);
        Assert.True(empty.Contains(12, 0));
        Assert.False(empty.Contains(11, 0));
        Assert.False(empty.Contains(12, 1));
    }

    [Fact]
    [Trait("Category", "Binary")]
    public void LoadMapRoundTripsFileAndVirtualRanges()
    {
        var result = ElfParser.Parse(ElfFixture.MinimalPie());
        Assert.NotNull(result.File);

        for (ulong offset = 0x200; offset < 0x204; offset++)
        {
            Assert.True(result.File!.LoadMap.TryFileOffsetToVirtualAddress(offset, out var virtualAddress));
            Assert.True(result.File.LoadMap.TryVirtualAddressToFileOffset(virtualAddress, out var roundTrip));
            Assert.Equal(offset, roundTrip);

            Assert.True(result.File.LoadMap.TryFileOffsetToVirtualAddress(new FileOffset(offset), out VirtualAddress typedVirtualAddress));
            Assert.True(result.File.LoadMap.TryVirtualAddressToFileOffset(typedVirtualAddress, out FileOffset typedRoundTrip));
            Assert.Equal(offset, typedRoundTrip.Value);
        }
    }

    [Fact]
    [Trait("Category", "Binary")]
    public void RuntimeAddressMappingRejectsUnderflowAndOverflow()
    {
        Assert.False(LoadMap.TryRuntimeAddressToVirtualAddress(3, 4, out _));
        Assert.True(LoadMap.TryRuntimeAddressToVirtualAddress(7, 4, out var virtualAddress));
        Assert.Equal(3UL, virtualAddress);

        Assert.True(LoadMap.TryVirtualAddressToRuntimeAddress(3, 4, out var runtimeAddress));
        Assert.Equal(7UL, runtimeAddress);
        Assert.False(LoadMap.TryVirtualAddressToRuntimeAddress(ulong.MaxValue, 1, out _));

        Assert.True(LoadMap.TryRuntimeAddressToVirtualAddress(new RuntimeAddress(7), 4, out VirtualAddress typedVirtualAddress));
        Assert.Equal(3UL, typedVirtualAddress.Value);
        Assert.True(LoadMap.TryVirtualAddressToRuntimeAddress(new VirtualAddress(3), 4, out RuntimeAddress typedRuntimeAddress));
        Assert.Equal(7UL, typedRuntimeAddress.Value);
    }
}
