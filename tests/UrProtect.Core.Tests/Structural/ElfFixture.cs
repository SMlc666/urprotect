using System.Buffers.Binary;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.ArtifactProtocol;

namespace UrProtect.Core.Tests.Structural;

internal static partial class ElfFixture
{
    public const int MinimalSize = 0x204;
    public const int FirstProgramHeaderOffset = ElfConstants.HeaderSize64;
    public const int SecondProgramHeaderOffset = FirstProgramHeaderOffset + ElfConstants.ProgramHeaderSize64;
    public const int DynamicProgramHeaderOffset = SecondProgramHeaderOffset + ElfConstants.ProgramHeaderSize64;
    public const int InterpreterProgramHeaderOffset = DynamicProgramHeaderOffset + ElfConstants.ProgramHeaderSize64;
    public const int DynamicTableOffset = 0x180;
    public const int InterpreterOffset = 0x1C0;
    public const int EntryInstructionOffset = 0x200;

    public static byte[] MinimalPie()
    {
        var bytes = new byte[MinimalSize];
        var span = bytes.AsSpan();
        span[0] = 0x7F;
        span[1] = (byte)'E';
        span[2] = (byte)'L';
        span[3] = (byte)'F';
        span[4] = ElfConstants.Class64;
        span[5] = ElfConstants.LittleEndian;
        span[6] = 1;
        WriteUInt16(span, 16, ElfConstants.TypeDyn);
        WriteUInt16(span, 18, ElfConstants.MachineAarch64);
        WriteUInt32(span, 20, 1);
        WriteUInt64(span, 24, 0x1200);
        WriteUInt64(span, 32, 64);
        WriteUInt64(span, 40, 0);
        WriteUInt32(span, 48, 0);
        WriteUInt16(span, 52, ElfConstants.HeaderSize64);
        WriteUInt16(span, 54, ElfConstants.ProgramHeaderSize64);
        WriteUInt16(span, 56, 4);
        WriteUInt16(span, 58, ElfConstants.SectionHeaderSize64);
        WriteUInt16(span, 60, 0);
        WriteUInt16(span, 62, 0);

        WriteProgramHeader(span, FirstProgramHeaderOffset, ElfConstants.PtLoad, ElfConstants.PfR, 0, 0, 0x200, 0x200, 0x1000);
        WriteProgramHeader(span, SecondProgramHeaderOffset, ElfConstants.PtLoad, ElfConstants.PfR | ElfConstants.PfX, 0x200, 0x1200, 4, 4, 0x1000);
        WriteProgramHeader(span, DynamicProgramHeaderOffset, ElfConstants.PtDynamic, ElfConstants.PfR, DynamicTableOffset, DynamicTableOffset, 32, 32, 8);
        const string interpreter = "/lib/ld-linux-aarch64.so.1\0";
        WriteUInt64(span, DynamicTableOffset, ElfConstants.DtFlags1);
        WriteUInt64(span, DynamicTableOffset + 8, ElfConstants.Df1Pie);
        WriteUInt64(span, DynamicTableOffset + 16, ElfConstants.DtNull);
        WriteUInt64(span, DynamicTableOffset + 24, 0);

        WriteProgramHeader(
            span,
            InterpreterProgramHeaderOffset,
            ElfConstants.PtInterp,
            ElfConstants.PfR,
            InterpreterOffset,
            InterpreterOffset,
            (ulong)Encoding.ASCII.GetByteCount(interpreter),
            (ulong)Encoding.ASCII.GetByteCount(interpreter),
            1);
        Encoding.ASCII.GetBytes(interpreter).CopyTo(span[InterpreterOffset..]);

        // NOP at the ET_DYN entry point.
        WriteUInt32(span, EntryInstructionOffset, 0xD503201F);
        return bytes;
    }

    public static byte[] TlsPie()
    {
        var bytes = MinimalPie();
        Array.Resize(ref bytes, 0x220);
        var phdrOffset = FirstProgramHeaderOffset + (4 * ElfConstants.ProgramHeaderSize64);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.ProgramHeaderCount, 5);
        WriteProgramHeader(
            bytes.AsSpan(),
            phdrOffset,
            ElfConstants.PtTls,
            ElfConstants.PfR,
            0x1E0,
            0x1E0,
            4,
            8,
            4);
        bytes[0x1E0] = 0x11;
        bytes[0x1E1] = 0x22;
        bytes[0x1E2] = 0x33;
        bytes[0x1E3] = 0x44;
        return bytes;
    }

    public static byte[] TlsRelocationPie(uint relocationType = ElfConstants.RArm64TlsLeMovwTprelG1)
    {
        var bytes = TlsPie();
        var tlsHeaderOffset = FirstProgramHeaderOffset + (4 * ElfConstants.ProgramHeaderSize64);
        WriteUInt64(bytes.AsSpan(), tlsHeaderOffset + ElfProgramHeaderOffsets.FileOffset, 0x1D8);
        WriteUInt64(bytes.AsSpan(), tlsHeaderOffset + ElfProgramHeaderOffsets.VirtualAddress, 0x1D8);
        WriteUInt64(bytes.AsSpan(), tlsHeaderOffset + ElfProgramHeaderOffsets.Alignment, 4);
        bytes.AsSpan(InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        WriteUInt64(bytes.AsSpan(), DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize, 5 * ElfConstants.DynamicEntrySize64);
        WriteUInt64(bytes.AsSpan(), DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize, 5 * ElfConstants.DynamicEntrySize64);
        WriteDynamicEntry(bytes.AsSpan(), DynamicTableOffset, ElfConstants.DtRela, 0x1E0);
        WriteDynamicEntry(bytes.AsSpan(), DynamicTableOffset + 16, ElfConstants.DtRelaSz, ElfConstants.RelaEntrySize64);
        WriteDynamicEntry(bytes.AsSpan(), DynamicTableOffset + 32, ElfConstants.DtRelaEnt, ElfConstants.RelaEntrySize64);
        WriteDynamicEntry(bytes.AsSpan(), DynamicTableOffset + 48, ElfConstants.DtFlags1, ElfConstants.Df1Pie);
        WriteDynamicEntry(bytes.AsSpan(), DynamicTableOffset + 64, ElfConstants.DtNull, 0);
        WriteUInt64(bytes.AsSpan(), 0x1E0, 0x1200);
        WriteUInt64(bytes.AsSpan(), 0x1E8, relocationType);
        WriteUInt64(bytes.AsSpan(), 0x1F0, 0);
        return bytes;
    }

    public static byte[] TlsStaticRelocationPie()
    {
        var bytes = TlsPie();
        Array.Resize(ref bytes, 0x480);
        WriteUInt64(bytes.AsSpan(), ElfHeaderOffsets.SectionHeaderOffset, 0x300);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.SectionHeaderEntrySize, ElfConstants.SectionHeaderSize64);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.SectionHeaderCount, 6);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.SectionNameIndex, 0);

        WriteSectionHeader(bytes.AsSpan(), 0x300 + ElfConstants.SectionHeaderSize64,
            ElfConstants.ShtStrTab, 0, 0, 0x2A0, 11, 0, 0, 1, 0);
        WriteSectionHeader(bytes.AsSpan(), 0x300 + (2 * ElfConstants.SectionHeaderSize64),
            ElfConstants.ShtSymTab, 0, 0, 0x260, 48, 1, 0, 8, ElfConstants.SymbolEntrySize64);
        WriteSectionHeader(bytes.AsSpan(), 0x300 + (3 * ElfConstants.SectionHeaderSize64),
            1, 0x403, 0x1E0, 0x1E0, 4, 0, 0, 4, 0);
        WriteSectionHeader(bytes.AsSpan(), 0x300 + (4 * ElfConstants.SectionHeaderSize64),
            1, 6, 0x1200, 0x200, 4, 0, 0, 4, 0);
        WriteSectionHeader(bytes.AsSpan(), 0x300 + (5 * ElfConstants.SectionHeaderSize64),
            ElfConstants.ShtRela, 0, 0, 0x240, ElfConstants.RelaEntrySize64, 2, 4, 8, ElfConstants.RelaEntrySize64);

        "\0tls_value\0"u8.CopyTo(bytes.AsSpan(0x2A0));
        WriteUInt32(bytes.AsSpan(), 0x278, 1);
        bytes[0x27C] = (byte)((1 << 4) | ElfConstants.SttTls);
        WriteUInt16(bytes.AsSpan(), 0x27E, 3);
        WriteUInt64(bytes.AsSpan(), 0x280, 0);
        WriteUInt64(bytes.AsSpan(), 0x288, 4);
        WriteUInt64(bytes.AsSpan(), 0x240, 0x1200);
        WriteUInt64(bytes.AsSpan(), 0x248, (1UL << 32) | ElfConstants.RArm64TlsIeAdrGottprelPage21);
        WriteUInt64(bytes.AsSpan(), 0x250, 0);
        return bytes;
    }

    public static byte[] TlsLocalExecFunctionPie()
    {
        var bytes = TlsStaticRelocationPie();
        Array.Resize(ref bytes, 0x700);
        const int codeOffset = 0x200;
        const int codeSize = 7 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int stringTableOffset = 0x580;
        const int symbolTableOffset = 0x500;
        const int relocationTableOffset = 0x600;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (1 * ElfConstants.SectionHeaderSize64) + 24, stringTableOffset);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (1 * ElfConstants.SectionHeaderSize64) + 32, 23);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (2 * ElfConstants.SectionHeaderSize64) + 24, symbolTableOffset);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (2 * ElfConstants.SectionHeaderSize64) + 32, 3 * ElfConstants.SymbolEntrySize64);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (5 * ElfConstants.SectionHeaderSize64) + 24, relocationTableOffset);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (5 * ElfConstants.SectionHeaderSize64) + 32, 2 * ElfConstants.RelaEntrySize64);

        // Preserve the existing TLS symbol as symbol 1 and add one selected STT_FUNC.
        bytes.AsSpan(0x278, ElfConstants.SymbolEntrySize64).CopyTo(bytes.AsSpan(symbolTableOffset + ElfConstants.SymbolEntrySize64));
        WriteUInt32(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64), 11);
        bytes[symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 4] = (byte)((1 << 4) | 2);
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 6),
            4);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 8, 0x1200);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);
        "\0tls_value\0tls_fixture\0"u8.CopyTo(bytes.AsSpan(stringTableOffset));

        WriteUInt64(bytes.AsSpan(), relocationTableOffset, 0x1204);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + 8, (1UL << 32) | ElfConstants.RArm64TlsLeAddTprelHi12);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + 16, 0);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64, 0x1208);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 8, (1UL << 32) | ElfConstants.RArm64TlsLeAddTprelLo12Nc);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 16, 0);

        var words = new uint[]
        {
            0xD53BD040, // MRS x0, TPIDR_EL0
            0x91400000, // ADD x0, x0, #0, LSL #12 (HI12 relocation)
            0x91000000, // ADD x0, x0, #0 (LO12 relocation)
            0xB9400009, // LDR w9, [x0]
            0xAA0903EA, // MOV x10, x9
            0xAA0A03E9, // MOV x9, x10
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return bytes;
    }

    public static byte[] ExactIndirectBranchFunctionPie(
        ulong targetAddress = 0x1208,
        bool useIndirectCall = false)
    {
        var bytes = TlsLocalExecFunctionPie();
        const int codeOffset = 0x200;
        const int codeSize = 3 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int relocationTableOffset = 0x600;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        // Remove the TLS relocation table from this non-TLS control-flow fixture.
        WriteUInt64(bytes.AsSpan(), DynamicTableOffset, ElfConstants.DtNull);
        WriteUInt64(bytes.AsSpan(), DynamicTableOffset + 8, 0);
        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderStart + (5 * ElfConstants.SectionHeaderSize64),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0);
        bytes.AsSpan(relocationTableOffset, 2 * ElfConstants.RelaEntrySize64).Clear();

        var encoder = new Aarch64InstructionEncoder();
        var movz = encoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.MoveWideImmediate,
            0x1200,
            targetAddress,
            DestinationRegister: 0,
            DestinationWidth: 64,
            ImmediateShift: 0));
        if (!movz.IsSuccess)
        {
            throw new InvalidOperationException(movz.Diagnostic);
        }

        WriteUInt32(bytes.AsSpan(), codeOffset, movz.Encoding);
        WriteUInt32(bytes.AsSpan(), codeOffset + sizeof(uint), useIndirectCall ? 0xD63F0000u : 0xD61F0000u);
        WriteUInt32(bytes.AsSpan(), codeOffset + (2 * sizeof(uint)), 0xD65F03C0u);
        return bytes;
    }

    public static byte[] ConditionalRegisterBranchFunctionPie(uint branchEncoding)
    {
        var bytes = ExactIndirectBranchFunctionPie();
        const int codeOffset = 0x200;
        WriteUInt32(bytes.AsSpan(), codeOffset, branchEncoding);
        WriteUInt32(bytes.AsSpan(), codeOffset + sizeof(uint), 0xD65F03C0u);
        WriteUInt32(bytes.AsSpan(), codeOffset + (2 * sizeof(uint)), 0xD65F03C0u);
        return bytes;
    }

    public static byte[] HostContextJoinClearedByReleaseStorePie()
    {
        var bytes = ExactIndirectBranchFunctionPie();
        const int codeOffset = 0x200;
        const int functionAddress = 0x1200;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int codeSize = 18 * sizeof(uint);
        const int successIndex = 7;
        const int failureIndex = 16;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            functionAddress,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        var words = new uint[18];
        words[0] = 0xAA0003E6u; // MOV X6, X0 (HostContext root for this selected test entry)
        words[1] = 0xF94004C1u; // LDR X1, [X6, #8]
        words[2] = EncodeTestBranch(functionAddress + (2 * sizeof(uint)), functionAddress + (failureIndex * sizeof(uint)), 1, 4, false);
        words[3] = 0xB94004C2u; // LDR W2, [X6, #4]
        var compare = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (4 * sizeof(uint)),
            72,
            BaseRegister: 2,
            DestinationWidth: 32));
        if (!compare.IsSuccess)
        {
            throw new InvalidOperationException(compare.Diagnostic);
        }

        words[4] = compare.Encoding;
        words[5] = EncodeConditionalBranch(
            functionAddress + (5 * sizeof(uint)),
            functionAddress + (successIndex * sizeof(uint)),
            conditionCode: 2);
        words[6] = 0xD65F03C0u; // RET (short-table failure)
        words[7] = 0xF9401CC3u; // LDR X3, [X6, #56]
        words[8] = EncodeCompareAndBranch(functionAddress + (8 * sizeof(uint)), functionAddress + (failureIndex * sizeof(uint)), 3, 64, false);
        words[9] = 0xF94020C4u; // LDR X4, [X6, #64]
        words[10] = EncodeCompareAndBranch(functionAddress + (10 * sizeof(uint)), functionAddress + (failureIndex * sizeof(uint)), 4, 64, false);
        words[11] = 0x910100C9u; // ADD X9, X6, #64 (the review counterexample's host-field alias)
        words[12] = 0xC89FFD3Fu; // STLR XZR, [X9]
        words[13] = 0xF94020C4u; // LDR X4, [X6, #64] (reload after the nulling write)
        words[14] = 0xD63F0080u; // BLR X4
        words[15] = 0xD65F03C0u; // RET
        words[16] = 0x52800020u; // MOV W0, #1
        words[17] = 0xD65F03C0u; // RET

        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return AddHostContextDynamicEntry(bytes, codeSize);
    }

    public static byte[] HostContextJoinCallbackIntactPie()
    {
        var bytes = HostContextJoinClearedByReleaseStorePie();
        WriteUInt32(bytes.AsSpan(), 0x200 + (11 * sizeof(uint)), 0xD503201Fu);
        WriteUInt32(bytes.AsSpan(), 0x200 + (12 * sizeof(uint)), 0xD503201Fu);
        return bytes;
    }

    public static byte[] HostContextJoinCallbackCmpBranchPie(int conditionCode = 0)
    {
        if (conditionCode is not (0 or 1))
        {
            throw new ArgumentOutOfRangeException(nameof(conditionCode));
        }

        const int codeOffset = 0x200;
        const ulong functionAddress = 0x1200;
        const int comparisonIndex = 10;
        const int branchIndex = 11;
        const int failureIndex = 16;
        var bytes = HostContextJoinCallbackIntactPie();
        var compare = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (comparisonIndex * sizeof(uint)),
            0,
            BaseRegister: 4,
            DestinationWidth: 64));
        if (!compare.IsSuccess)
        {
            throw new InvalidOperationException(compare.Diagnostic);
        }

        WriteUInt32(bytes.AsSpan(), codeOffset + (comparisonIndex * sizeof(uint)), compare.Encoding);
        WriteUInt32(
            bytes.AsSpan(),
            codeOffset + (branchIndex * sizeof(uint)),
            EncodeConditionalBranch(
                functionAddress + (branchIndex * sizeof(uint)),
                functionAddress + (failureIndex * sizeof(uint)),
                conditionCode));
        return bytes;
    }

    public static byte[] HostContextJoinCallbackAddressBearingMutationPie(uint memoryInstructionEncoding)
    {
        var bytes = HostContextJoinCallbackIntactPie();
        const int codeOffset = 0x200;
        const ulong functionAddress = 0x1200;
        const int addressIndex = 11;
        const int atomicIndex = 12;
        var addAddress = functionAddress + (addressIndex * sizeof(uint));
        var add = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AddImmediate,
            addAddress,
            64,
            DestinationRegister: 9,
            BaseRegister: 6,
            DestinationWidth: 64));
        if (!add.IsSuccess)
        {
            throw new InvalidOperationException(add.Diagnostic);
        }

        WriteUInt32(bytes.AsSpan(), codeOffset + (addressIndex * sizeof(uint)), add.Encoding);
        // The instruction word is a named AArch64 oracle asserted by adapter tests.
        WriteUInt32(bytes.AsSpan(), codeOffset + (atomicIndex * sizeof(uint)), memoryInstructionEncoding);
        return bytes;
    }

    public static byte[] HostContextSizeStoreAfterComparisonPie()
    {
        var bytes = HostContextJoinClearedByReleaseStorePie();
        const int codeOffset = 0x200;
        const int functionAddress = 0x1200;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int codeSize = 20 * sizeof(uint);
        const int failureIndex = 18;
        var words = new uint[20];
        words[0] = 0xAA0003E6u;
        words[1] = 0xF94004C1u;
        words[2] = EncodeTestBranch(functionAddress + (2 * sizeof(uint)), functionAddress + (failureIndex * sizeof(uint)), 1, 4, false);
        words[3] = 0xB94004C2u;
        var compare = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (4 * sizeof(uint)),
            72,
            BaseRegister: 2,
            DestinationWidth: 32));
        if (!compare.IsSuccess)
        {
            throw new InvalidOperationException(compare.Diagnostic);
        }

        words[4] = compare.Encoding;
        words[5] = 0x910010C9u; // ADD X9, X6, #4 (HostContext size field)
        words[6] = 0x889FFD3Fu; // STLR WZR, [X9]
        words[7] = EncodeConditionalBranch(
            functionAddress + (7 * sizeof(uint)),
            functionAddress + (9 * sizeof(uint)),
            conditionCode: 2);
        words[8] = 0xD65F03C0u;
        words[9] = 0xF9401CC3u;
        words[10] = EncodeCompareAndBranch(functionAddress + (10 * sizeof(uint)), functionAddress + (failureIndex * sizeof(uint)), 3, 64, false);
        words[11] = 0xF94020C4u;
        words[12] = EncodeCompareAndBranch(functionAddress + (12 * sizeof(uint)), functionAddress + (failureIndex * sizeof(uint)), 4, 64, false);
        words[13] = 0xD503201Fu;
        words[14] = 0xD503201Fu;
        words[15] = 0xF94020C4u;
        words[16] = 0xD63F0080u;
        words[17] = 0xD65F03C0u;
        words[18] = 0x52800020u;
        words[19] = 0xD65F03C0u;
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        WriteProgramHeader(bytes.AsSpan(), SecondProgramHeaderOffset, ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX, codeOffset, functionAddress, codeSize, codeSize, 0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);
        UpdateHostContextDynamicEntrySize(bytes, codeSize);
        return bytes;
    }

    public static byte[] HostContextCallbackWithUnrelatedTlsStorePie()
    {
        var bytes = HostContextJoinClearedByReleaseStorePie();
        WriteUInt32(bytes.AsSpan(), 0x200 + (11 * sizeof(uint)), 0xD53BD049u); // MRS X9, TPIDR_EL0
        return bytes;
    }

    public static byte[] HostContextCallbackProducerChainPie(int moveAliasCount)
    {
        if (moveAliasCount < 0 || moveAliasCount > 256)
        {
            throw new ArgumentOutOfRangeException(nameof(moveAliasCount));
        }

        var bytes = ExactIndirectBranchFunctionPie();
        const int codeOffset = 0x200;
        const int functionAddress = 0x1200;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int moveStartIndex = 11;
        var callIndex = checked(moveStartIndex + moveAliasCount);
        var failureIndex = checked(callIndex + 2);
        var instructionCount = checked(failureIndex + 2);
        var codeSize = checked(instructionCount * sizeof(uint));

        var words = new uint[instructionCount];
        words[0] = 0xAA0003F3u; // MOV X19, X0 (HostContext root)
        words[1] = 0xF9400661u; // LDR X1, [X19, #8]
        words[2] = EncodeTestBranch(functionAddress + (2 * sizeof(uint)), checked((ulong)(functionAddress + (failureIndex * sizeof(uint)))), 1, 4, false);
        words[3] = 0xB9400662u; // LDR W2, [X19, #4]
        var compare = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (4 * sizeof(uint)),
            72,
            BaseRegister: 2,
            DestinationWidth: 32));
        if (!compare.IsSuccess)
        {
            throw new InvalidOperationException(compare.Diagnostic);
        }

        words[4] = compare.Encoding;
        words[5] = EncodeConditionalBranch(
            functionAddress + (5 * sizeof(uint)),
            functionAddress + (7 * sizeof(uint)),
            conditionCode: 2);
        words[6] = 0xD65F03C0u; // RET (short-table failure)
        words[7] = 0xF9401E63u; // LDR X3, [X19, #56]
        words[8] = EncodeCompareAndBranch(functionAddress + (8 * sizeof(uint)), checked((ulong)(functionAddress + (failureIndex * sizeof(uint)))), 3, 64, false);
        words[9] = 0xF9402264u; // LDR X4, [X19, #64]
        words[10] = EncodeCompareAndBranch(functionAddress + (10 * sizeof(uint)), checked((ulong)(functionAddress + (failureIndex * sizeof(uint)))), 4, 64, false);
        for (var index = 0; index < moveAliasCount; index++)
        {
            words[moveStartIndex + index] = index == 0 ? 0xAA0403E9u : 0xAA0903E9u;
        }

        words[callIndex] = 0xD63F0120u; // BLR X9
        words[callIndex + 1] = 0xD65F03C0u; // RET
        words[failureIndex] = 0x52800020u; // MOV W0, #1
        words[failureIndex + 1] = 0xD65F03C0u; // RET

        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            functionAddress,
            checked((ulong)codeSize),
            checked((ulong)codeSize),
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, checked((ulong)codeSize));
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, checked((ulong)codeSize));
        return AddHostContextDynamicEntry(bytes, checked((ulong)codeSize));
    }


    public static byte[] HostContextCallbackProducerMergePie()
    {
        var bytes = HostContextCallbackProducerChainPie(62);
        const int codeOffset = 0x200;
        const int functionAddress = 0x1200;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int pathAStart = 12;
        const int aliasesPerPath = 31;
        const int pathABranch = 44;
        const int pathBStart = 45;
        const int pathBBranch = 77;
        const int joinIndex = 78;
        const int failureIndex = 80;
        const int instructionCount = 82;
        const ulong codeSize = instructionCount * sizeof(uint);
        ulong AddressAt(int index) => checked((ulong)(functionAddress + (index * sizeof(uint))));

        var words = new uint[instructionCount];
        words[0] = 0xAA0003F3u;
        words[1] = 0xF9400661u;
        words[2] = EncodeTestBranch(AddressAt(2), AddressAt(failureIndex), 1, 4, false);
        words[3] = 0xB9400662u;
        var compare = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate, AddressAt(4), 72, BaseRegister: 2, DestinationWidth: 32));
        if (!compare.IsSuccess)
        {
            throw new InvalidOperationException(compare.Diagnostic);
        }

        words[4] = compare.Encoding;
        words[5] = EncodeConditionalBranch(AddressAt(5), AddressAt(7), 2);
        words[6] = 0xD65F03C0u;
        words[7] = 0xF9401E63u;
        words[8] = EncodeCompareAndBranch(AddressAt(8), AddressAt(failureIndex), 3, 64, false);
        words[9] = 0xF9402264u;
        words[10] = EncodeCompareAndBranch(AddressAt(10), AddressAt(failureIndex), 4, 64, false);
        words[11] = EncodeCompareAndBranch(AddressAt(11), AddressAt(pathBStart), 0, 32, false);
        words[pathAStart] = 0xF9402269u;
        for (var index = 0; index < aliasesPerPath; index++)
        {
            words[pathAStart + index + 1] = 0xAA0903E9u;
        }

        var branchA = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Branch26, AddressAt(pathABranch), AddressAt(joinIndex)));
        var branchB = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Branch26, AddressAt(pathBBranch), AddressAt(joinIndex)));
        if (!branchA.IsSuccess || !branchB.IsSuccess)
        {
            throw new InvalidOperationException(!branchA.IsSuccess ? branchA.Diagnostic : branchB.Diagnostic);
        }

        words[pathABranch] = branchA.Encoding;
        words[pathBStart] = 0xF9402269u;
        for (var index = 0; index < aliasesPerPath; index++)
        {
            words[pathBStart + index + 1] = 0xAA0903E9u;
        }

        words[pathBBranch] = branchB.Encoding;
        words[joinIndex] = 0xD63F0120u;
        words[joinIndex + 1] = 0xD65F03C0u;
        words[failureIndex] = 0x52800020u;
        words[failureIndex + 1] = 0xD65F03C0u;
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        WriteProgramHeader(bytes.AsSpan(), SecondProgramHeaderOffset, ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX, codeOffset, functionAddress, codeSize, codeSize, 0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);
        UpdateHostContextDynamicEntrySize(bytes, codeSize);
        return bytes;
    }

    public static byte[] HostContextCallbackAfterUnknownCallPie()
    {
        var bytes = ExactIndirectBranchFunctionPie();
        const int codeOffset = 0x200;
        const int functionAddress = 0x1200;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int codeSize = 19 * sizeof(uint);
        const int successIndex = 9;
        const int failureIndex = 17;
        const int capabilityBranchIndex = 3;
        const int sizeBranchIndex = 6;
        const int createNullBranchIndex = 10;
        const int joinNullBranchIndex = 12;
        const int callbackCallIndex = 15;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            functionAddress,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        var words = new uint[19];
        words[0] = 0xD10083FFu; // SUB SP, SP, #0x20
        words[1] = 0xAA0003F3u; // MOV X19, X0 (HostContext; callee-saved)
        words[2] = 0xF9400661u; // LDR X1, [X19, #8]
        words[capabilityBranchIndex] = EncodeTestBranch(
            functionAddress + (capabilityBranchIndex * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 1,
            bit: 4,
            nonZero: false);
        words[4] = 0xB9400662u; // LDR W2, [X19, #4]
        var compare = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (5 * sizeof(uint)),
            72,
            BaseRegister: 2,
            DestinationWidth: 32));
        if (!compare.IsSuccess)
        {
            throw new InvalidOperationException(compare.Diagnostic);
        }

        words[5] = compare.Encoding;
        words[sizeBranchIndex] = EncodeConditionalBranch(
            functionAddress + (sizeBranchIndex * sizeof(uint)),
            functionAddress + (successIndex * sizeof(uint)),
            conditionCode: 2); // B.HS: struct_size >= 72
        words[7] = 0x52800020u; // MOV W0, #1
        words[8] = 0xD65F03C0u; // RET (short-table failure)
        words[9] = 0xF9401E63u; // LDR X3, [X19, #56]
        words[createNullBranchIndex] = EncodeCompareAndBranch(
            functionAddress + (createNullBranchIndex * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 3,
            width: 64,
            nonZero: false);
        words[11] = 0xF9402264u; // LDR X4, [X19, #64]
        words[joinNullBranchIndex] = EncodeCompareAndBranch(
            functionAddress + (joinNullBranchIndex * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 4,
            width: 64,
            nonZero: false);
        var call = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.Call26,
            functionAddress + (13 * sizeof(uint)),
            0x1100));
        if (!call.IsSuccess)
        {
            throw new InvalidOperationException(call.Diagnostic);
        }

        words[13] = call.Encoding;
        words[14] = 0xF9401E69u; // LDR X9, [X19, #56] (reload without a fresh null check)
        words[callbackCallIndex] = 0xD63F0120u; // BLR X9
        words[16] = 0xD65F03C0u; // RET
        words[failureIndex] = 0x52800020u; // MOV W0, #1
        words[18] = 0xD65F03C0u; // RET

        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return AddHostContextDynamicEntry(bytes, codeSize);
    }

    public static byte[] HostContextCallbackWithEscapedStackArgumentPie()
    {
        var bytes = ExactIndirectBranchFunctionPie();
        const int codeOffset = 0x200;
        const int functionAddress = 0x1200;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int codeSize = 34 * sizeof(uint);
        const int failureIndex = 32;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            functionAddress,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        var words = new uint[34];
        words[0] = 0xD10103FFu; // SUB SP, SP, #0x40
        words[1] = 0xF90003E0u; // STR X0, [SP] (retain the HostContext pointer in a stack slot)
        words[2] = 0xAA0003F3u; // MOV X19, X0
        words[3] = 0xF9400661u; // LDR X1, [X19, #8]
        words[4] = EncodeTestBranch(
            functionAddress + (4 * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 1,
            bit: 4,
            nonZero: false);
        words[5] = 0xB9400662u; // LDR W2, [X19, #4]
        words[6] = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (6 * sizeof(uint)),
            72,
            BaseRegister: 2,
            DestinationWidth: 32)).Encoding;
        words[7] = EncodeConditionalBranch(
            functionAddress + (7 * sizeof(uint)),
            functionAddress + (10 * sizeof(uint)),
            conditionCode: 2);
        words[8] = 0x52800020u; // MOV W0, #1
        words[9] = 0xD65F03C0u; // RET
        words[10] = 0xF9401E63u; // LDR X3, [X19, #56]
        words[11] = EncodeCompareAndBranch(
            functionAddress + (11 * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 3,
            width: 64,
            nonZero: false);
        words[12] = 0xF9402264u; // LDR X4, [X19, #64]
        words[13] = EncodeCompareAndBranch(
            functionAddress + (13 * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 4,
            width: 64,
            nonZero: false);
        words[14] = 0x910083E4u; // ADD X4, SP, #0x20 (callback output pointer)
        words[15] = 0xD2800013u; // MOVZ X19, #0 (force subsequent recovery through the stack slot)
        words[16] = 0xD63F0060u; // BLR X3
        words[17] = 0xF94003F3u; // LDR X19, [SP]
        words[18] = 0xF9400661u; // LDR X1, [X19, #8]
        words[19] = EncodeTestBranch(
            functionAddress + (19 * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 1,
            bit: 4,
            nonZero: false);
        words[20] = 0xB9400662u; // LDR W2, [X19, #4]
        words[21] = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.CompareImmediate,
            functionAddress + (21 * sizeof(uint)),
            72,
            BaseRegister: 2,
            DestinationWidth: 32)).Encoding;
        words[22] = EncodeConditionalBranch(
            functionAddress + (22 * sizeof(uint)),
            functionAddress + (25 * sizeof(uint)),
            conditionCode: 2);
        words[23] = 0x52800020u; // MOV W0, #1
        words[24] = 0xD65F03C0u; // RET
        words[25] = 0xF9401E63u; // LDR X3, [X19, #56]
        words[26] = EncodeCompareAndBranch(
            functionAddress + (26 * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 3,
            width: 64,
            nonZero: false);
        words[27] = 0xF9402264u; // LDR X4, [X19, #64]
        words[28] = EncodeCompareAndBranch(
            functionAddress + (28 * sizeof(uint)),
            functionAddress + (failureIndex * sizeof(uint)),
            register: 4,
            width: 64,
            nonZero: false);
        words[29] = 0xF9402270u; // LDR X16, [X19, #64]
        words[30] = 0xD63F0200u; // BLR X16
        words[31] = 0xD65F03C0u; // RET
        words[failureIndex] = 0x52800020u; // MOV W0, #1
        words[33] = 0xD65F03C0u; // RET

        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return AddHostContextDynamicEntry(bytes, codeSize);
    }

    private static byte[] AddHostContextDynamicEntry(byte[] bytes, ulong functionSize)
    {
        Array.Resize(ref bytes, 0x780);
        var span = bytes.AsSpan();
        WriteUInt64(span, ElfHeaderOffsets.Entry, 0);
        const int dynamicEntryCount = 7;
        const int hashFileOffset = 0x700;
        const int symbolFileOffset = 0x720;
        const int stringFileOffset = 0x750;
        const ulong hashVirtualAddress = 0x1700;
        const ulong symbolVirtualAddress = 0x1720;
        const ulong stringVirtualAddress = 0x1750;
        const ulong functionAddress = 0x1200;
        var entryName = "\0urp_entry\0"u8;

        WriteProgramHeader(
            span,
            InterpreterProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR,
            hashFileOffset,
            hashVirtualAddress,
            0x80,
            0x80,
            1);
        WriteUInt64(span, DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize,
            checked((ulong)dynamicEntryCount * ElfConstants.DynamicEntrySize64));
        WriteUInt64(span, DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize,
            checked((ulong)dynamicEntryCount * ElfConstants.DynamicEntrySize64));

        var dynamicEntries = new (ulong Tag, ulong Value)[]
        {
            (ElfConstants.DtHash, hashVirtualAddress),
            (ElfConstants.DtStrTab, stringVirtualAddress),
            (ElfConstants.DtStrSz, checked((ulong)entryName.Length)),
            (ElfConstants.DtSymTab, symbolVirtualAddress),
            (ElfConstants.DtSymEnt, ElfConstants.SymbolEntrySize64),
            (ElfConstants.DtFlags1, ElfConstants.Df1Pie),
            (ElfConstants.DtNull, 0),
        };
        for (var index = 0; index < dynamicEntries.Length; index++)
        {
            WriteDynamicEntry(
                span,
                DynamicTableOffset + (index * ElfConstants.DynamicEntrySize64),
                dynamicEntries[index].Tag,
                dynamicEntries[index].Value);
        }

        WriteUInt32(span, hashFileOffset, 1);
        WriteUInt32(span, hashFileOffset + sizeof(uint), 2);
        WriteUInt32(span, hashFileOffset + (2 * sizeof(uint)), 1);
        WriteUInt32(span, hashFileOffset + (3 * sizeof(uint)), 0);
        WriteUInt32(span, hashFileOffset + (4 * sizeof(uint)), 0);

        var symbolOffset = symbolFileOffset + ElfConstants.SymbolEntrySize64;
        WriteUInt32(span, symbolOffset, 1);
        span[symbolOffset + 4] = (byte)((1 << 4) | ElfConstants.SttFunc);
        WriteUInt16(span, symbolOffset + 6, 4);
        WriteUInt64(span, symbolOffset + 8, functionAddress);
        WriteUInt64(span, symbolOffset + 16, functionSize);
        entryName.CopyTo(span[stringFileOffset..]);
        return bytes;
    }

    private static void UpdateHostContextDynamicEntrySize(byte[] bytes, ulong functionSize) =>
        WriteUInt64(
            bytes.AsSpan(),
            0x720 + ElfConstants.SymbolEntrySize64 + 16,
            functionSize);

    private static uint EncodeTestBranch(ulong address, ulong target, byte register, int bit, bool nonZero)
    {
        var displacement = checked((long)target - (long)address);
        if (displacement % sizeof(uint) != 0 || displacement / sizeof(uint) is < -8192 or > 8191)
        {
            throw new ArgumentOutOfRangeException(nameof(target));
        }

        var immediate = unchecked((uint)(displacement / sizeof(uint))) & 0x3FFFu;
        return (nonZero ? 0x37000000u : 0x36000000u)
            | (checked((uint)bit) << 19)
            | (immediate << 5)
            | register;
    }

    private static uint EncodeCompareAndBranch(
        ulong address,
        ulong target,
        byte register,
        int width,
        bool nonZero)
    {
        var displacement = checked((long)target - (long)address);
        if (displacement % sizeof(uint) != 0 || displacement / sizeof(uint) is < -262144 or > 262143)
        {
            throw new ArgumentOutOfRangeException(nameof(target));
        }

        var immediate = unchecked((uint)(displacement / sizeof(uint))) & 0x7FFFFu;
        var widthBit = width == 64 ? 0x80000000u : 0u;
        return widthBit
            | (nonZero ? 0x35000000u : 0x34000000u)
            | (immediate << 5)
            | register;
    }

    private static uint EncodeConditionalBranch(ulong address, ulong target, int conditionCode)
    {
        var displacement = checked((long)target - (long)address);
        if (displacement % sizeof(uint) != 0 || displacement / sizeof(uint) is < -262144 or > 262143)
        {
            throw new ArgumentOutOfRangeException(nameof(target));
        }

        var immediate = unchecked((uint)(displacement / sizeof(uint))) & 0x7FFFFu;
        return 0x54000000u | (immediate << 5) | checked((uint)conditionCode);
    }

    public static byte[] RelativeJumpTableFunctionPie(
        bool malformedTableEntry = false,
        bool clobberCheckedIndexWithTableBase = false,
        bool outOfExecutableLoadRangeTableEntry = false)
    {
        var bytes = ExactIndirectBranchFunctionPie();
        const int codeOffset = 0x200;
        const int codeSize = 0x48;
        const int tableOffset = codeOffset + codeSize;
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            0x58,
            0x58,
            0x1000);
        WriteUInt64(
            bytes.AsSpan(),
            sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32,
            codeSize);
        WriteUInt64(
            bytes.AsSpan(),
            symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16,
            codeSize);

        var words = new uint[]
        {
            0x71000C1F, // CMP W0, #3
            0x540001E8, // B.HI default
            0x90000001, // ADRP X1, table page
            0x91092021, // ADD X1, X1, #0x248
            0xB8A05822, // LDRSW X2, [X1, W0, UXTW #2]
            0x10000063, // ADR X3, case0
            0x8B020061, // ADD X1, X3, X2
            0xD61F0020, // BR X1
            0x52800220, // case0: MOV W0, #17
            0xD65F03C0, // RET
            0x52800CE0, // case1: MOV W0, #103
            0xD65F03C0, // RET
            0x128000C0, // case2: MOV W0, #-7
            0xD65F03C0, // RET
            0x52800B60, // case3: MOV W0, #91
            0xD65F03C0, // RET
            0x12800000, // default: MOV W0, #-1
            0xD65F03C0, // RET
        };
        if (clobberCheckedIndexWithTableBase)
        {
            // GNU-as equivalents: ADRP X0, table page; ADD X0, X0, #0x248;
            // LDRSW X2, [X0, W0, UXTW #2]. This keeps the decoded table
            // pattern intact while the X0 table-base setup overwrites checked W0.
            words[2] = 0x90000000;
            words[3] = 0x91092000;
            words[4] = 0xB8A05802;
        }

        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        if (malformedTableEntry && outOfExecutableLoadRangeTableEntry)
        {
            throw new ArgumentException("Select only one malformed relative jump-table mutation.");
        }

        var entries = malformedTableEntry
            ? new[] { 40u, 8u, 16u, 24u }
            : outOfExecutableLoadRangeTableEntry
                ? new[] { 0x7FFFFFE0u, 8u, 16u, 24u }
                : new[] { 0u, 8u, 16u, 24u };
        for (var index = 0; index < entries.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), tableOffset + (index * sizeof(uint)), entries[index]);
        }

        return bytes;
    }

    public static byte[] TlsLocalExecMovwFunctionPie(
        long relocationAddend = 0,
        bool useMovn = false,
        bool interleavePair = false)
    {
        var bytes = TlsLocalExecFunctionPie();
        const int codeOffset = 0x200;
        var codeSize = (interleavePair ? 7 : 6) * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int relocationTableOffset = 0x600;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            (ulong)codeSize,
            (ulong)codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, (ulong)codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, (ulong)codeSize);

        WriteUInt64(bytes.AsSpan(), relocationTableOffset, 0x1200);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + 8, (1UL << 32) | ElfConstants.RArm64TlsLeMovwTprelG1);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(relocationTableOffset + 16), relocationAddend);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64, interleavePair ? 0x1208UL : 0x1204UL);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 8, (1UL << 32) | ElfConstants.RArm64TlsLeMovwTprelG0Nc);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(relocationTableOffset + ElfConstants.RelaEntrySize64 + 16), relocationAddend);

        var words = interleavePair
            ? new uint[]
            {
                useMovn ? 0x92A00009u : 0xD2A00009u, // MOVN/MOVZ x9, #imm, LSL #16 (G1)
                0xD53BD04A, // MRS x10, TPIDR_EL0 (interleaved)
                0xF2800009, // MOVK x9, #imm (G0_NC)
                0x8B090149, // ADD x9, x10, x9
                0xB9400120, // LDR w0, [x9]
                0xAA0003EA, // MOV x10, x0
                0xD65F03C0, // RET
            }
            : new uint[]
            {
                useMovn ? 0x92A00009u : 0xD2A00009u, // MOVN/MOVZ x9, #imm, LSL #16 (G1)
                0xF2800009, // MOVK x9, #imm (G0_NC)
                0xD53BD04A, // MRS x10, TPIDR_EL0
                0x8B090149, // ADD x9, x10, x9
                0xB9400120, // LDR w0, [x9]
                0xD65F03C0, // RET
            };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return bytes;
    }

    /// <summary>
    /// GNU AArch64 TLSIE ADRP/LD64 GOTTPREL shape with a source-preserved
    /// writable GOT entry owned by R_AARCH64_TLS_TPREL64. The source relocation
    /// fields retain the relocatable zero page/low-12 encoding; shared layout
    /// resolves the output fields against the preserved GOT address.
    /// </summary>
    public static byte[] TlsInitialExecAdrLd64FunctionPie(long relocationAddend = 0)
    {
        var bytes = TlsInitialExecMovwFunctionPie(relocationAddend);
        const int codeOffset = 0x200;
        const int codeSize = 6 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int relocationTableOffset = 0x600;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 8,
            (1UL << 32) | ElfConstants.RArm64TlsIeAdrGottprelPage21);
        BinaryPrimitives.WriteInt64LittleEndian(
            bytes.AsSpan(relocationTableOffset + ElfConstants.RelaEntrySize64 + 16),
            relocationAddend);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + (2 * ElfConstants.RelaEntrySize64) + 8,
            (1UL << 32) | ElfConstants.RArm64TlsIeLd64GottprelLo12Nc);
        BinaryPrimitives.WriteInt64LittleEndian(
            bytes.AsSpan(relocationTableOffset + (2 * ElfConstants.RelaEntrySize64) + 16),
            relocationAddend);

        var words = new uint[]
        {
            0x90000009, // ADRP x9, :gottprel:tls_value (page relocation)
            0xF9400129, // LDR x9, [x9] (LD64 low-12 relocation)
            0xD53BD04A, // MRS x10, TPIDR_EL0
            0x8B090149, // ADD x9, x10, x9 (TLS address)
            0xB9400120, // LDR w0, [x9]
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        bytes.AsSpan(codeOffset + codeSize, sizeof(uint) * 2).Clear();
        return bytes;
    }

    /// <summary>
    /// GCC initial-exec register-offset access: the GOT-loaded TPREL value is
    /// consumed directly by an indexed scalar LDR after the TP read.
    /// </summary>
    public static byte[] TlsInitialExecAdrLd64RegisterOffsetFunctionPie(long relocationAddend = 0)
    {
        var bytes = TlsInitialExecAdrLd64FunctionPie(relocationAddend);
        const int codeOffset = 0x200;
        const int codeSize = 5 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;

        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);
        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);

        // mrs x10, tpidr_el0 and ldr w0, [x10, x9] consume the TP read in
        // x10 and GOT-loaded TPREL in x9, matching GCC's register-offset form.
        WriteUInt32(bytes.AsSpan(), codeOffset + (3 * sizeof(uint)), 0xB8696940);
        WriteUInt32(bytes.AsSpan(), codeOffset + (4 * sizeof(uint)), 0xD65F03C0);
        bytes.AsSpan(codeOffset + codeSize, sizeof(uint) * 3).Clear();
        return bytes;
    }
    /// <summary>
    /// GNU TLSIE standalone literal-load form: one PREL19 instruction relocation
    /// targets the source-preserved writable TPREL64 GOT owner.
    /// </summary>
    public static byte[] TlsInitialExecLdGotPrel19FunctionPie(long relocationAddend = 0)
    {
        var bytes = TlsInitialExecMovwFunctionPie(relocationAddend);
        const int codeOffset = 0x200;
        const int codeSize = 5 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int relocationTableOffset = 0x600;

        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (5 * ElfConstants.SectionHeaderSize64) + 32,
            2 * ElfConstants.RelaEntrySize64);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64, 0x1200);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 8,
            (1UL << 32) | ElfConstants.RArm64TlsIeLdGottprelPrel19);
        BinaryPrimitives.WriteInt64LittleEndian(
            bytes.AsSpan(relocationTableOffset + ElfConstants.RelaEntrySize64 + 16),
            relocationAddend);

        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), 0x500 + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);
        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);

        var words = new uint[]
        {
            0x58000009, // LDR x9, :gottprel:tls_value (PREL19)
            0xD53BD04A, // MRS x10, TPIDR_EL0
            0x8B090149, // ADD x9, x10, x9
            0xB9400120, // LDR w0, [x9]
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return bytes;
    }

    public static byte[] TlsInitialExecMovwFunctionPie(
        long relocationAddend = 0,
        bool useMovn = false)
    {
        var bytes = TlsLocalExecFunctionPie();
        const int codeOffset = 0x200;
        const int codeSize = 8 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int relocationTableOffset = 0x600;

        // The first load owns the PT_TLS template and the source-preserved GOT
        // entry at 0x1D0; it must be writable for the loader-owned TPREL64 slot.
        WriteUInt32(bytes.AsSpan(), FirstProgramHeaderOffset + ElfProgramHeaderOffsets.Flags, ElfConstants.PfR | ElfConstants.PfW);
        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (5 * ElfConstants.SectionHeaderSize64) + 32, 3 * ElfConstants.RelaEntrySize64);

        // GOT owner: R_AARCH64_TLS_TPREL64 tls_value + addend.
        WriteUInt64(bytes.AsSpan(), relocationTableOffset, 0x1D0);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + 8, (1UL << 32) | ElfConstants.RArm64TlsTprel64);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(relocationTableOffset + 16), relocationAddend);
        // Exact adjacent TLSIE MOVW pair.
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64, 0x1200);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 8, (1UL << 32) | ElfConstants.RArm64TlsIeMovwGottprelG1);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(relocationTableOffset + ElfConstants.RelaEntrySize64 + 16), relocationAddend);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + (2 * ElfConstants.RelaEntrySize64), 0x1204);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + (2 * ElfConstants.RelaEntrySize64) + 8, (1UL << 32) | ElfConstants.RArm64TlsIeMovwGottprelG0Nc);
        BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(relocationTableOffset + (2 * ElfConstants.RelaEntrySize64) + 16), relocationAddend);

        var words = new uint[]
        {
            useMovn ? 0x92A00009u : 0xD2A00009u, // MOVN/MOVZ x9, #imm, LSL #16 (G1)
            0xF2800009, // MOVK x9, #imm (G0_NC)
            0xD53BD04A, // MRS x10, TPIDR_EL0
            0x8B090149, // ADD x9, x10, x9 (GOT address)
            0xF9400129, // LDR x9, [x9] (GOT TPREL value)
            0x8B090149, // ADD x9, x10, x9 (TLS address)
            0xB9400120, // LDR w0, [x9]
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return bytes;
    }

    /// <summary>
    /// GNU AArch64 emits this local-exec form as ADD_TPREL_HI12 followed by
    /// LDST32_TPREL_LO12_NC. The symbol is placed at byte offset four so the
    /// unsigned-immediate encoding exercises its scale-four low-12 field.
    /// </summary>
    public static byte[] TlsLocalExecLdst32FunctionPie(bool useStore = false)
    {
        var bytes = TlsLocalExecFunctionPie();
        const int codeOffset = 0x200;
        const int codeSize = 4 * sizeof(uint);
        const int sectionHeaderStart = 0x300;
        const int symbolTableOffset = 0x500;
        const int relocationTableOffset = 0x600;

        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1200,
            codeSize,
            codeSize,
            0x1000);
        WriteUInt64(bytes.AsSpan(), sectionHeaderStart + (4 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        // The STT_TLS symbol resides in the initialized PT_TLS template at
        // byte offset four, keeping the LDST32 offset aligned to its scale.
        WriteUInt64(bytes.AsSpan(), symbolTableOffset + ElfConstants.SymbolEntrySize64 + 8, 4);
        BinaryPrimitives.WriteUInt16LittleEndian(
            bytes.AsSpan(symbolTableOffset + ElfConstants.SymbolEntrySize64 + 6),
            3);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset, 0x1204);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + 8, (1UL << 32) | ElfConstants.RArm64TlsLeAddTprelHi12);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64, 0x1208);
        WriteUInt64(bytes.AsSpan(), relocationTableOffset + ElfConstants.RelaEntrySize64 + 8, (1UL << 32) | ElfConstants.RArm64TlsLeLdst32TprelLo12Nc);

        var words = new uint[]
        {
            0xD53BD04A, // MRS x10, TPIDR_EL0
            0x91400149, // ADD x9, x10, #0, LSL #12 (HI12)
            useStore ? 0xB9000520u : 0xB9400520u, // STR/LDR w0, [x9, #4] (LO12_NC, scale 4)
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }

        return bytes;
    }

    /// <summary>
    /// Exact TLSLD ADRP/ADD, __tls_get_addr CALL26, and DTPREL ADD/ADD shape
    /// with a loader-owned DTPMOD64 GOT slot and PLT resolver owner.
    /// </summary>
    public static byte[] TlsLocalDynamicFunctionPie(long dtprelAddend = 4, bool useNonNcDtprelLow = false)
    {
        var bytes = MinimalPie();
        Array.Resize(ref bytes, 0xB00);
        const int codeOffset = 0x600;
        const int codeSize = 9 * sizeof(uint);
        const int dynamicTableOffset = 0x180;
        const int tlsOffset = 0x260;
        const int moduleGotOffset = 0x2A0;
        const int resolverGotOffset = 0x2A8;
        const int relaOffset = 0x300;
        const int pltRelaOffset = 0x318;
        const int dynamicSymbolOffset = 0x360;
        const int dynamicStringOffset = 0x3A0;
        const int hashOffset = 0x3C0;
        const int staticRelaOffset = 0x4E0;
        const int staticSymbolOffset = 0x700;
        const int staticStringOffset = 0x780;
        const int sectionHeaderOffset = 0x900;

        WriteUInt64(bytes.AsSpan(), ElfHeaderOffsets.Entry, 0x1600);
        WriteUInt64(bytes.AsSpan(), ElfHeaderOffsets.SectionHeaderOffset, sectionHeaderOffset);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.SectionHeaderEntrySize, ElfConstants.SectionHeaderSize64);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.SectionHeaderCount, 7);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.SectionNameIndex, 0);
        WriteUInt16(bytes.AsSpan(), ElfHeaderOffsets.ProgramHeaderCount, 5);

        WriteProgramHeader(
            bytes.AsSpan(),
            FirstProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfW,
            0,
            0,
            0x600,
            0x600,
            0x1000);
        WriteProgramHeader(
            bytes.AsSpan(),
            SecondProgramHeaderOffset,
            ElfConstants.PtLoad,
            ElfConstants.PfR | ElfConstants.PfX,
            codeOffset,
            0x1600,
            0x80,
            0x80,
            0x1000);

        var dynamicEntries = new (ulong Tag, ulong Value)[]
        {
            (ElfConstants.DtHash, hashOffset),
            (ElfConstants.DtStrTab, dynamicStringOffset),
            (ElfConstants.DtStrSz, 16),
            (ElfConstants.DtSymTab, dynamicSymbolOffset),
            (ElfConstants.DtSymEnt, ElfConstants.SymbolEntrySize64),
            (ElfConstants.DtRela, relaOffset),
            (ElfConstants.DtRelaSz, ElfConstants.RelaEntrySize64),
            (ElfConstants.DtRelaEnt, ElfConstants.RelaEntrySize64),
            (ElfConstants.DtJmpRel, pltRelaOffset),
            (ElfConstants.DtPltRelSz, ElfConstants.RelaEntrySize64),
            (ElfConstants.DtPltRel, ElfConstants.DtRela),
            (ElfConstants.DtFlags1, ElfConstants.Df1Pie),
            (ElfConstants.DtNull, 0),
        };
        WriteProgramHeader(
            bytes.AsSpan(),
            DynamicProgramHeaderOffset,
            ElfConstants.PtDynamic,
            ElfConstants.PfR,
            dynamicTableOffset,
            dynamicTableOffset,
            checked((ulong)(dynamicEntries.Length * ElfConstants.DynamicEntrySize64)),
            checked((ulong)(dynamicEntries.Length * ElfConstants.DynamicEntrySize64)),
            8);
        for (var index = 0; index < dynamicEntries.Length; index++)
        {
            WriteDynamicEntry(
                bytes.AsSpan(),
                dynamicTableOffset + (index * ElfConstants.DynamicEntrySize64),
                dynamicEntries[index].Tag,
                dynamicEntries[index].Value);
        }

        const string interpreter = "/lib/ld-linux-aarch64.so.1\0";
        WriteProgramHeader(
            bytes.AsSpan(),
            InterpreterProgramHeaderOffset,
            ElfConstants.PtInterp,
            ElfConstants.PfR,
            0x580,
            0x580,
            (ulong)Encoding.ASCII.GetByteCount(interpreter),
            (ulong)Encoding.ASCII.GetByteCount(interpreter),
            1);
        Encoding.ASCII.GetBytes(interpreter).CopyTo(bytes.AsSpan(0x580));

        WriteProgramHeader(
            bytes.AsSpan(),
            FirstProgramHeaderOffset + (4 * ElfConstants.ProgramHeaderSize64),
            ElfConstants.PtTls,
            ElfConstants.PfR | ElfConstants.PfW,
            tlsOffset,
            tlsOffset,
            8,
            24,
            8);
        WriteUInt64(bytes.AsSpan(), tlsOffset, 0x11223344AABBCCDD);
        WriteUInt64(bytes.AsSpan(), moduleGotOffset, 0);
        WriteUInt64(bytes.AsSpan(), resolverGotOffset, 0);

        WriteUInt64(bytes.AsSpan(), relaOffset, moduleGotOffset);
        WriteUInt64(bytes.AsSpan(), relaOffset + 8, ElfConstants.RArm64TlsDtpMod64);
        WriteUInt64(bytes.AsSpan(), relaOffset + 16, 0);
        WriteUInt64(bytes.AsSpan(), pltRelaOffset, resolverGotOffset);
        WriteUInt64(bytes.AsSpan(), pltRelaOffset + 8, (1UL << 32) | ElfConstants.RArm64JumpSlot);
        WriteUInt64(bytes.AsSpan(), pltRelaOffset + 16, 0);

        WriteUInt32(bytes.AsSpan(), hashOffset, 1);
        WriteUInt32(bytes.AsSpan(), hashOffset + 4, 2);
        WriteUInt32(bytes.AsSpan(), hashOffset + 8, 1);
        WriteUInt32(bytes.AsSpan(), hashOffset + 12, 0);
        WriteUInt32(bytes.AsSpan(), hashOffset + 16, 1);
        "\0__tls_get_addr\0"u8.CopyTo(bytes.AsSpan(dynamicStringOffset));
        WriteUInt32(bytes.AsSpan(), dynamicSymbolOffset + ElfConstants.SymbolEntrySize64, 1);
        bytes[dynamicSymbolOffset + ElfConstants.SymbolEntrySize64 + 4] = (byte)((1 << 4) | ElfConstants.SttFunc);
        WriteUInt16(bytes.AsSpan(), dynamicSymbolOffset + ElfConstants.SymbolEntrySize64 + 6, 0);

        var staticRelocations = new (ulong Address, uint Type, long Addend)[]
        {
            (0x1600, ElfConstants.RArm64TlsLdAdrPage21, 0),
            (0x1604, ElfConstants.RArm64TlsLdAddLo12Nc, 0),
            (0x160C, ElfConstants.RArm64TlsLdAddDtprelHi12, dtprelAddend),
            (0x1610, useNonNcDtprelLow
                ? ElfConstants.RArm64TlsLdAddDtprelLo12
                : ElfConstants.RArm64TlsLdAddDtprelLo12Nc, dtprelAddend),
        };
        for (var index = 0; index < staticRelocations.Length; index++)
        {
            var offset = staticRelaOffset + (index * ElfConstants.RelaEntrySize64);
            WriteUInt64(bytes.AsSpan(), offset, staticRelocations[index].Address);
            WriteUInt64(bytes.AsSpan(), offset + 8, (1UL << 32) | staticRelocations[index].Type);
            WriteUInt64(bytes.AsSpan(), offset + 16, unchecked((ulong)staticRelocations[index].Addend));
        }

        "\0tls_value\0tls_fixture\0"u8.CopyTo(bytes.AsSpan(staticStringOffset));
        var staticTlsSymbolOffset = staticSymbolOffset + ElfConstants.SymbolEntrySize64;
        WriteUInt32(bytes.AsSpan(), staticTlsSymbolOffset, 1);
        bytes[staticTlsSymbolOffset + 4] = (byte)((1 << 4) | ElfConstants.SttTls);
        WriteUInt16(bytes.AsSpan(), staticTlsSymbolOffset + 6, 1);
        WriteUInt64(bytes.AsSpan(), staticTlsSymbolOffset + 8, 4);
        WriteUInt64(bytes.AsSpan(), staticTlsSymbolOffset + 16, 4);
        var staticFunctionSymbolOffset = staticSymbolOffset + (2 * ElfConstants.SymbolEntrySize64);
        WriteUInt32(bytes.AsSpan(), staticFunctionSymbolOffset, 11);
        bytes[staticFunctionSymbolOffset + 4] = (byte)((1 << 4) | ElfConstants.SttFunc);
        WriteUInt16(bytes.AsSpan(), staticFunctionSymbolOffset + 6, 3);
        WriteUInt64(bytes.AsSpan(), staticFunctionSymbolOffset + 8, 0x1600);
        WriteUInt64(bytes.AsSpan(), staticFunctionSymbolOffset + 16, codeSize);

        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderOffset + ElfConstants.SectionHeaderSize64,
            ElfConstants.ShtStrTab,
            0,
            0,
            dynamicStringOffset,
            16,
            0,
            0,
            1,
            0);
        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderOffset + (2 * ElfConstants.SectionHeaderSize64),
            ElfConstants.ShtDynSym,
            0,
            dynamicSymbolOffset,
            dynamicSymbolOffset,
            2 * ElfConstants.SymbolEntrySize64,
            1,
            1,
            8,
            ElfConstants.SymbolEntrySize64);
        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderOffset + (3 * ElfConstants.SectionHeaderSize64),
            1,
            6,
            0x1600,
            codeOffset,
            codeSize,
            0,
            0,
            4,
            0);
        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderOffset + (4 * ElfConstants.SectionHeaderSize64),
            ElfConstants.ShtRela,
            0,
            staticRelaOffset,
            staticRelaOffset,
            4 * ElfConstants.RelaEntrySize64,
            5,
            3,
            8,
            ElfConstants.RelaEntrySize64);
        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderOffset + (5 * ElfConstants.SectionHeaderSize64),
            ElfConstants.ShtSymTab,
            0,
            0,
            staticSymbolOffset,
            3 * ElfConstants.SymbolEntrySize64,
            6,
            2,
            8,
            ElfConstants.SymbolEntrySize64);
        WriteSectionHeader(
            bytes.AsSpan(),
            sectionHeaderOffset + (6 * ElfConstants.SectionHeaderSize64),
            ElfConstants.ShtStrTab,
            0,
            0,
            staticStringOffset,
            23,
            0,
            0,
            1,
            0);

        var words = new uint[]
        {
            0x90000000, // ADRP x0, :tlsldm:tls_value
            0x91000000, // ADD x0, x0, :tlsldm_lo12_nc:tls_value
            0x9400000E, // BL __tls_get_addr PLT stub at 0x1640
            0x91400000, // ADD x0, x0, #:dtprel_hi12:tls_value+4
            0x91000000, // ADD x0, x0, #:dtprel_lo12_nc:tls_value+4
            0xB9400000, // LDR w0, [x0]
            0xAA0003E9, // MOV x9, x0
            0xAA0903EA, // MOV x10, x9
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x40, 0xF0FFFFF0); // ADRP x16, page of TLSLD resolver GOT slot
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x44, 0xF9415611); // LDR x17, [x16, #0x2A8]
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x48, 0x910AA210); // ADD x16, x16, #0x2A8
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x4C, 0xD61F0220); // BR x17

        return bytes;
    }

    /// <summary>Exact TLSGD ADRP/ADD, __tls_get_addr CALL26, final access, and paired DTPMOD64/DTPREL64 owners.</summary>
    public static byte[] TlsGeneralDynamicFunctionPie(long dtprelAddend = 0)
    {
        var bytes = TlsLocalDynamicFunctionPie(dtprelAddend);
        const int codeOffset = 0x600;
        const int codeSize = 7 * sizeof(uint);
        const int dynamicTableOffset = 0x180;
        const int dynamicRelaOffset = 0x300;
        const int pltRelaOffset = 0x330;
        const int dynamicSymbolOffset = 0x360;
        const int dynamicStringOffset = 0x3B0;
        const int hashOffset = 0x3D0;
        const int staticRelaOffset = 0x4E0;
        const int sectionHeaderOffset = 0x900;

        WriteUInt64(bytes.AsSpan(), sectionHeaderOffset + (3 * ElfConstants.SectionHeaderSize64) + 32, codeSize);
        WriteUInt64(bytes.AsSpan(), sectionHeaderOffset + (4 * ElfConstants.SectionHeaderSize64) + 32, 2 * ElfConstants.RelaEntrySize64);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 8, hashOffset);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 24, dynamicStringOffset);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 40, 26);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 56, dynamicSymbolOffset);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 104, 2 * ElfConstants.RelaEntrySize64);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 136, pltRelaOffset);
        WriteUInt64(bytes.AsSpan(), dynamicTableOffset + 152, ElfConstants.RelaEntrySize64);

        bytes.AsSpan(dynamicStringOffset, 26).Clear();
        "\0__tls_get_addr\0tls_value\0"u8.CopyTo(bytes.AsSpan(dynamicStringOffset));
        WriteUInt32(bytes.AsSpan(), dynamicSymbolOffset + (2 * ElfConstants.SymbolEntrySize64), 16);
        bytes[dynamicSymbolOffset + (2 * ElfConstants.SymbolEntrySize64) + 4] = (byte)((1 << 4) | ElfConstants.SttTls);
        WriteUInt16(bytes.AsSpan(), dynamicSymbolOffset + (2 * ElfConstants.SymbolEntrySize64) + 6, 1);
        WriteUInt64(bytes.AsSpan(), dynamicSymbolOffset + (2 * ElfConstants.SymbolEntrySize64) + 8, 4);
        WriteUInt64(bytes.AsSpan(), dynamicSymbolOffset + (2 * ElfConstants.SymbolEntrySize64) + 16, 4);

        bytes.AsSpan(hashOffset, 20).Clear();
        WriteUInt32(bytes.AsSpan(), hashOffset, 1);
        WriteUInt32(bytes.AsSpan(), hashOffset + 4, 3);
        WriteUInt32(bytes.AsSpan(), hashOffset + 8, 1);
        WriteUInt32(bytes.AsSpan(), hashOffset + 12, 0);
        WriteUInt32(bytes.AsSpan(), hashOffset + 16, 2);

        WriteUInt64(bytes.AsSpan(), dynamicRelaOffset, 0x2A0);
        WriteUInt64(bytes.AsSpan(), dynamicRelaOffset + 8, (2UL << 32) | ElfConstants.RArm64TlsDtpMod64);
        WriteUInt64(bytes.AsSpan(), dynamicRelaOffset + 16, 0);
        WriteUInt64(bytes.AsSpan(), dynamicRelaOffset + ElfConstants.RelaEntrySize64, 0x2A8);
        WriteUInt64(bytes.AsSpan(), dynamicRelaOffset + ElfConstants.RelaEntrySize64 + 8, (2UL << 32) | ElfConstants.RArm64TlsDtpRel64);
        WriteUInt64(bytes.AsSpan(), dynamicRelaOffset + ElfConstants.RelaEntrySize64 + 16, unchecked((ulong)dtprelAddend));
        WriteUInt64(bytes.AsSpan(), pltRelaOffset, 0x2B0);
        WriteUInt64(bytes.AsSpan(), pltRelaOffset + 8, (1UL << 32) | ElfConstants.RArm64JumpSlot);
        WriteUInt64(bytes.AsSpan(), pltRelaOffset + 16, 0);
        WriteUInt64(bytes.AsSpan(), 0x2B0, 0);

        WriteUInt64(bytes.AsSpan(), staticRelaOffset, 0x1600);
        WriteUInt64(bytes.AsSpan(), staticRelaOffset + 8, (1UL << 32) | ElfConstants.RArm64TlsGdAdrPage21);
        WriteUInt64(bytes.AsSpan(), staticRelaOffset + 16, 0);
        WriteUInt64(bytes.AsSpan(), staticRelaOffset + ElfConstants.RelaEntrySize64, 0x1604);
        WriteUInt64(bytes.AsSpan(), staticRelaOffset + ElfConstants.RelaEntrySize64 + 8, (1UL << 32) | ElfConstants.RArm64TlsGdAddLo12Nc);
        WriteUInt64(bytes.AsSpan(), staticRelaOffset + ElfConstants.RelaEntrySize64 + 16, 0);
        WriteUInt64(bytes.AsSpan(), 0x700 + (2 * ElfConstants.SymbolEntrySize64) + 16, codeSize);

        var words = new uint[]
        {
            0x90000000, // ADRP x0, :tlsgd:tls_value
            0x91000000, // ADD x0, x0, :tlsgd_lo12:tls_value
            0x9400000E, // BL __tls_get_addr PLT stub
            0xB9400000, // LDR w0, [x0]
            0xAA0003E9, // MOV x9, x0
            0xAA0903EA, // MOV x10, x9
            0xD65F03C0, // RET
        };
        for (var index = 0; index < words.Length; index++)
        {
            WriteUInt32(bytes.AsSpan(), codeOffset + (index * sizeof(uint)), words[index]);
        }
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x40, 0xF0FFFFF0); // ADRP x16, page of TLSGD resolver GOT slot
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x44, 0xF9415A11); // LDR x17, [x16, #0x2B0]
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x48, 0x910AC210); // ADD x16, x16, #0x2B0
        WriteUInt32(bytes.AsSpan(), codeOffset + 0x4C, 0xD61F0220); // BR x17

        return bytes;
    }
    public static byte[] CongruentNonPageSizedLoadAlignmentPie()
    {
        var bytes = MinimalPie();
        WriteUInt64(bytes.AsSpan(), 64 + 48, 0x200);
        WriteUInt64(bytes.AsSpan(), 120 + 48, 0x200);
        return bytes;
    }

    public static byte[] StaticPieLauncher(bool includeMarker = true)
    {
        var bytes = MinimalPie();
        bytes.AsSpan(232, 56).Clear();
        if (!includeMarker)
        {
            return bytes;
        }

        return bytes.Concat(Encoding.ASCII.GetBytes(LauncherContract.Marker)).ToArray();
    }

    public static byte[] StaticPiePayload()
    {
        var bytes = MinimalPie();
        bytes.AsSpan(InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        return bytes;
    }

    public static byte[] DynamicExecPayload()
    {
        var bytes = MinimalPie();
        WriteUInt16(bytes.AsSpan(), 16, ElfConstants.TypeExec);
        return bytes;
    }

    public static byte[] MinimalPieWithInterpreter(string interpreterPath) =>
        ReplaceInterpreter(MinimalPie(), interpreterPath);

    public static byte[] DynamicExecPayloadWithInterpreter(string interpreterPath) =>
        ReplaceInterpreter(DynamicExecPayload(), interpreterPath);

    public static byte[] StaticExecPayload()
    {
        var bytes = DynamicExecPayload();
        bytes.AsSpan(InterpreterProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        bytes.AsSpan(DynamicProgramHeaderOffset, ElfConstants.ProgramHeaderSize64).Clear();
        return bytes;
    }

    public static byte[] DynamicExecWithSearchPath(ulong searchPathTag)
    {
        if (searchPathTag is not (ElfConstants.DtRpath or ElfConstants.DtRunPath))
        {
            throw new ArgumentOutOfRangeException(nameof(searchPathTag));
        }

        var bytes = DynamicExecPayload();
        var span = bytes.AsSpan();
        const ulong dynamicSize = 5 * ElfConstants.DynamicEntrySize64;
        WriteUInt64(span, DynamicTableOffset, ElfConstants.DtFlags1);
        WriteUInt64(span, DynamicTableOffset + 8, ElfConstants.Df1Pie);
        WriteUInt64(span, DynamicTableOffset + 16, ElfConstants.DtStrTab);
        WriteUInt64(span, DynamicTableOffset + 24, 0x1D0);
        WriteUInt64(span, DynamicTableOffset + 32, ElfConstants.DtStrSz);
        WriteUInt64(span, DynamicTableOffset + 40, 6);
        WriteUInt64(span, DynamicTableOffset + 48, searchPathTag);
        WriteUInt64(span, DynamicTableOffset + 56, 1);
        WriteUInt64(span, DynamicTableOffset + 64, ElfConstants.DtNull);
        WriteUInt64(span, DynamicTableOffset + 72, 0);
        WriteUInt64(span, DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize, dynamicSize);
        WriteUInt64(span, DynamicProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize, dynamicSize);
        new byte[] { 0, (byte)'/', (byte)'t', (byte)'m', (byte)'p', 0 }.CopyTo(span[0x1D0..]);

        const string interpreter = "/lib/ld-linux-aarch64.so.1\0";
        WriteUInt64(span, InterpreterProgramHeaderOffset + ElfProgramHeaderOffsets.FileOffset, 0x1E0);
        WriteUInt64(span, InterpreterProgramHeaderOffset + ElfProgramHeaderOffsets.VirtualAddress, 0x1E0);
        WriteUInt64(span, InterpreterProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize,
            (ulong)Encoding.ASCII.GetByteCount(interpreter));
        WriteUInt64(span, InterpreterProgramHeaderOffset + ElfProgramHeaderOffsets.MemorySize,
            (ulong)Encoding.ASCII.GetByteCount(interpreter));
        Encoding.ASCII.GetBytes(interpreter).CopyTo(span[0x1E0..]);
        return bytes;
    }

    private static byte[] ReplaceInterpreter(byte[] bytes, string interpreterPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(interpreterPath);
        var interpreterSize = checked((int)BinaryPrimitives.ReadUInt64LittleEndian(
            bytes.AsSpan(InterpreterProgramHeaderOffset + ElfProgramHeaderOffsets.FileSize)));
        var encodedInterpreter = Encoding.ASCII.GetBytes(interpreterPath + '\0');
        if (encodedInterpreter.Length > interpreterSize)
        {
            throw new ArgumentException("The fixture interpreter does not fit in the PT_INTERP range.", nameof(interpreterPath));
        }

        var interpreter = bytes.AsSpan(InterpreterOffset, interpreterSize);
        interpreter.Clear();
        encodedInterpreter.CopyTo(interpreter);
        return bytes;
    }

    private static void WriteSectionHeader(
        Span<byte> destination,
        int offset,
        uint type,
        ulong flags,
        ulong address,
        ulong fileOffset,
        ulong size,
        uint link,
        uint info,
        ulong alignment,
        ulong entrySize)
    {
        WriteUInt32(destination, offset + 4, type);
        WriteUInt64(destination, offset + 8, flags);
        WriteUInt64(destination, offset + 16, address);
        WriteUInt64(destination, offset + 24, fileOffset);
        WriteUInt64(destination, offset + 32, size);
        WriteUInt32(destination, offset + 40, link);
        WriteUInt32(destination, offset + 44, info);
        WriteUInt64(destination, offset + 48, alignment);
        WriteUInt64(destination, offset + 56, entrySize);
    }

    private static void WriteProgramHeader(
        Span<byte> destination,
        int offset,
        uint type,
        uint flags,
        ulong fileOffset,
        ulong virtualAddress,
        ulong fileSize,
        ulong memorySize,
        ulong alignment)
    {
        WriteUInt32(destination, offset, type);
        WriteUInt32(destination, offset + 4, flags);
        WriteUInt64(destination, offset + 8, fileOffset);
        WriteUInt64(destination, offset + 16, virtualAddress);
        WriteUInt64(destination, offset + 24, 0);
        WriteUInt64(destination, offset + 32, fileSize);
        WriteUInt64(destination, offset + 40, memorySize);
        WriteUInt64(destination, offset + 48, alignment);
    }

    private static void WriteDynamicEntry(Span<byte> destination, int offset, ulong tag, ulong value)
    {
        WriteUInt64(destination, offset, tag);
        WriteUInt64(destination, offset + sizeof(ulong), value);
    }

    private static void WriteUInt16(Span<byte> destination, int offset, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(destination[offset..], value);

    private static void WriteUInt32(Span<byte> destination, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(destination[offset..], value);

    private static void WriteUInt64(Span<byte> destination, int offset, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(destination[offset..], value);
}
