using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Structural;

internal static partial class ElfFixture
{
    /// <summary>
    /// Exact eight-word TLSDESC sequence with one dynamic descriptor owner and
    /// the linker-created six-word resolver stub shape.
    /// </summary>
    public static byte[] TlsDescriptorFunctionPie()
    {
        var bytes = TlsLocalDynamicFunctionPie();
        Array.Resize(ref bytes, 0x2400);
        const int codeOffset = 0x600;
        const int codeSize = 8 * sizeof(uint);
        const int dynamicTableOffset = 0x200;
        const int dynamicSymbolOffset = 0x360;
        const int dynamicStringOffset = 0x3A0;
        const int hashOffset = 0x3C0;
        const int pltRelocationOffset = 0x318;
        const int staticRelocationOffset = 0x4E0;
        const int staticSymbolOffset = 0x700;
        const int staticStringOffset = 0x780;
        const int sectionHeaderOffset = 0x900;
        const ulong descriptorAddress = 0x1000;
        const ulong resolverGotAddress = 0x1020;
        const ulong pltGotAddress = 0x1030;
        const ulong resolverPltAddress = 0x1640;
        const int tlsHeaderOffset = FirstProgramHeaderOffset + (4 * ElfConstants.ProgramHeaderSize64);

        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.ProgramHeaderCount, 6);
        WriteProgramHeader(
            bytes.AsSpan(),
            tlsHeaderOffset,
            ElfConstants.PtTls,
            ElfConstants.PfR,
            0x300,
            0x300,
            4,
            24,
            8);
        WriteProgramHeader(
            bytes.AsSpan(),
            FirstProgramHeaderOffset + (5 * ElfConstants.ProgramHeaderSize64),
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfW,
            0x1000,
            0x1000,
            0x400,
            0x400,
            0x1000);
        WriteProgramHeader(
            bytes.AsSpan(),
            DynamicProgramHeaderOffset,
            ElfConstants.PtDynamic,
            ElfConstants.PfR,
            (ulong)dynamicTableOffset,
            (ulong)dynamicTableOffset,
            checked((ulong)(13 * ElfConstants.DynamicEntrySize64)),
            checked((ulong)(13 * ElfConstants.DynamicEntrySize64)),
            8);
        bytes.AsSpan(0x300, 24).Clear();
        bytes[0x300] = 0x44;
        bytes[0x301] = 0x33;
        bytes[0x302] = 0x22;
        bytes[0x303] = 0x11;

        var dynamicEntries = new (ulong Tag, ulong Value)[]
        {
            (ElfConstants.DtHash, hashOffset),
            (ElfConstants.DtStrTab, dynamicStringOffset),
            (ElfConstants.DtStrSz, 16),
            (ElfConstants.DtSymTab, dynamicSymbolOffset),
            (ElfConstants.DtSymEnt, ElfConstants.SymbolEntrySize64),
            (ElfConstants.DtJmpRel, pltRelocationOffset),
            (ElfConstants.DtPltRelSz, ElfConstants.RelaEntrySize64),
            (ElfConstants.DtPltRel, ElfConstants.DtRela),
            (ElfConstants.DtTlsDescPlt, resolverPltAddress),
            (ElfConstants.DtTlsDescGot, resolverGotAddress),
            (ElfConstants.DtPltGot, pltGotAddress),
            (ElfConstants.DtFlags1, ElfConstants.Df1Pie),
            (ElfConstants.DtNull, 0),
        };
        for (var index = 0; index < dynamicEntries.Length; index++)
        {
            WriteDynamicEntry(
                bytes.AsSpan(),
                dynamicTableOffset + (index * ElfConstants.DynamicEntrySize64),
                dynamicEntries[index].Tag,
                dynamicEntries[index].Value);
        }

        bytes.AsSpan(dynamicStringOffset, 16).Clear();
        "\0tls_desc_value\0"u8.CopyTo(bytes.AsSpan(dynamicStringOffset));
        bytes.AsSpan(dynamicSymbolOffset, 2 * ElfConstants.SymbolEntrySize64).Clear();
        var dynamicTlsSymbol = dynamicSymbolOffset + ElfConstants.SymbolEntrySize64;
        WriteUInt32(bytes.AsSpan(), dynamicTlsSymbol, 1);
        bytes[dynamicTlsSymbol + 4] = (byte)((1 << 4) | ElfConstants.SttTls);
        WriteUInt16(bytes.AsSpan(), dynamicTlsSymbol + 6, 1);
        WriteUInt64(bytes.AsSpan(), dynamicTlsSymbol + 8, 0);
        WriteUInt64(bytes.AsSpan(), dynamicTlsSymbol + 16, 4);

        bytes.AsSpan(hashOffset, 20).Clear();
        WriteUInt32(bytes.AsSpan(), hashOffset, 1);
        WriteUInt32(bytes.AsSpan(), hashOffset + 4, 2);
        WriteUInt32(bytes.AsSpan(), hashOffset + 8, 1);
        WriteUInt32(bytes.AsSpan(), hashOffset + 12, 0);
        WriteUInt32(bytes.AsSpan(), hashOffset + 16, 1);

        WriteUInt64(bytes.AsSpan(), pltRelocationOffset, descriptorAddress);
        WriteUInt64(
            bytes.AsSpan(),
            pltRelocationOffset + 8,
            (1UL << 32) | ElfConstants.RArm64TlsDesc);
        WriteUInt64(bytes.AsSpan(), pltRelocationOffset + 16, 0);

        var staticRelocations = new uint[]
        {
            ElfConstants.RArm64TlsDescAdrPage21,
            ElfConstants.RArm64TlsDescLd64Lo12,
            ElfConstants.RArm64TlsDescAddLo12,
            ElfConstants.RArm64TlsDescCall,
        };
        for (var index = 0; index < staticRelocations.Length; index++)
        {
            var relocationOffset = staticRelocationOffset + (index * ElfConstants.RelaEntrySize64);
            WriteUInt64(bytes.AsSpan(), relocationOffset, 0x1600UL + ((ulong)index * sizeof(uint)));
            WriteUInt64(
                bytes.AsSpan(),
                relocationOffset + 8,
                (1UL << 32) | staticRelocations[index]);
            WriteUInt64(bytes.AsSpan(), relocationOffset + 16, 0);
        }

        bytes.AsSpan(staticStringOffset, 32).Clear();
        "\0tls_desc_value\0tlsdesc_entry\0"u8.CopyTo(bytes.AsSpan(staticStringOffset));
        var staticTlsSymbol = staticSymbolOffset + ElfConstants.SymbolEntrySize64;
        WriteUInt32(bytes.AsSpan(), staticTlsSymbol, 1);
        bytes[staticTlsSymbol + 4] = (byte)((1 << 4) | ElfConstants.SttTls);
        WriteUInt16(bytes.AsSpan(), staticTlsSymbol + 6, 1);
        WriteUInt64(bytes.AsSpan(), staticTlsSymbol + 8, 0);
        WriteUInt64(bytes.AsSpan(), staticTlsSymbol + 16, 4);
        var staticFunctionSymbol = staticSymbolOffset + (2 * ElfConstants.SymbolEntrySize64);
        WriteUInt32(bytes.AsSpan(), staticFunctionSymbol, 16);
        bytes[staticFunctionSymbol + 4] = (byte)((1 << 4) | ElfConstants.SttFunc);
        WriteUInt16(bytes.AsSpan(), staticFunctionSymbol + 6, 3);
        WriteUInt64(bytes.AsSpan(), staticFunctionSymbol + 8, 0x1600);
        WriteUInt64(bytes.AsSpan(), staticFunctionSymbol + 16, codeSize);

        WriteUInt64(bytes.AsSpan(), sectionHeaderOffset + (3 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), sectionHeaderOffset + (6 * ElfConstants.SectionHeaderSize64) + 32, 30);

        var words = new uint[]
        {
            0x90000000, // ADRP x0, descriptor page 0x1000 from PC page 0x1000.
            0xF9400001, // LDR x1, [x0].
            0x91000000, // ADD x0, x0, #0.
            0xD63F0020, // BLR x1, marked R_AARCH64_TLSDESC_CALL.
            0xD53BD041, // MRS x1, TPIDR_EL0.
            0x8B000020, // ADD x0, x1, x0.
            0xB9400000, // LDR w0, [x0].
            0xD65F03C0, // RET.
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        var resolverWords = new uint[]
        {
            0xA9BF0FE2, // STP x2, x3, [sp, #-16]!
            0x90000002, // ADRP x2, resolver GOT page 0x1000 from PC page 0x1000.
            0x90000003, // ADRP x3, PLTGOT page 0x1000 from PC page 0x1000.
            0xF9401042, // LDR x2, [x2, #0x1020].
            0x9100C063, // ADD x3, x3, #0x1030.
            0xD61F0040, // BR x2.
        };
        for (var index = 0; index < resolverWords.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + 0x40 + (index * sizeof(uint)), resolverWords[index]);
        }

        bytes.AsSpan(checked((int)descriptorAddress), 2 * sizeof(ulong)).Clear();
        return bytes;
    }
}
