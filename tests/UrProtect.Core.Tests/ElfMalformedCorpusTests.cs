using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Tests;

public sealed class ElfMalformedCorpusTests
{
    public static IEnumerable<object[]> Corpus()
    {
        yield return Case("empty", Array.Empty<byte>(), DiagnosticCode.InputTooSmall);
        yield return Case("truncated-header", new byte[32], DiagnosticCode.InputTooSmall);
        yield return Case("bad-magic", new byte[ElfConstants.HeaderSize64], DiagnosticCode.InvalidMagic);

        var invalidClass = ElfFixture.MinimalPie();
        invalidClass[4] = 1;
        yield return Case("unsupported-class", invalidClass, DiagnosticCode.UnsupportedClass);

        var invalidEncoding = ElfFixture.MinimalPie();
        invalidEncoding[5] = 2;
        yield return Case("unsupported-endianness", invalidEncoding, DiagnosticCode.UnsupportedEndianness);

        var invalidIdentVersion = ElfFixture.MinimalPie();
        invalidIdentVersion[6] = 2;
        yield return Case("invalid-ident-version", invalidIdentVersion, DiagnosticCode.InvalidHeader);

        var invalidMachine = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt16LittleEndian(invalidMachine.AsSpan(18), 0x3E);
        yield return Case("unsupported-machine", invalidMachine, DiagnosticCode.UnsupportedMachine);

        var invalidType = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt16LittleEndian(invalidType.AsSpan(16), 2);
        yield return Case("unsupported-file-type", invalidType, DiagnosticCode.UnsupportedFileType);

        var overflowingProgramHeaders = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(overflowingProgramHeaders.AsSpan(32), ulong.MaxValue);
        yield return Case("program-header-range-overflow", overflowingProgramHeaders, DiagnosticCode.TableOutOfBounds);

        var invalidAlignment = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(invalidAlignment.AsSpan(64 + 48), 3);
        yield return Case("invalid-segment-alignment", invalidAlignment, DiagnosticCode.InvalidAlignment);

        var invalidSegment = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(invalidSegment.AsSpan(120 + 32), 8);
        BinaryPrimitives.WriteUInt64LittleEndian(invalidSegment.AsSpan(120 + 40), 4);
        yield return Case("file-size-exceeds-memory-size", invalidSegment, DiagnosticCode.InvalidSegment);

        var unmappedEntry = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(unmappedEntry.AsSpan(24), 0x100);
        yield return Case("entry-point-unmapped", unmappedEntry, DiagnosticCode.AddressUnmapped);

        var unterminatedDynamic = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt64LittleEndian(unterminatedDynamic.AsSpan(0x190), ElfConstants.DtNeeded);
        yield return Case("unterminated-dynamic-table", unterminatedDynamic, DiagnosticCode.DynamicTableUnterminated);
    }

    [Theory]
    [MemberData(nameof(Corpus))]
    [Trait("Category", "Malformed")]
    public void RejectsOrReportsMalformedCorpusEntry(
        string name,
        byte[] bytes,
        DiagnosticCode expectedCode)
    {
        var result = ElfParser.Parse(bytes);

        Assert.True(
            result.Diagnostics.Any(diagnostic => diagnostic.Code == expectedCode),
            $"{name}: expected diagnostic {expectedCode}; got {string.Join(", ", result.Diagnostics.Select(diagnostic => diagnostic.Code))}");
    }

    private static object[] Case(string name, byte[] bytes, DiagnosticCode expectedCode) =>
        new object[] { name, bytes, expectedCode };
}
