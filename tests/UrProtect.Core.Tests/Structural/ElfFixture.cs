using System.Buffers.Binary;
using System.Text;
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
    public static byte[] TlsLocalDynamicFunctionPie(long dtprelAddend = 4)
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
            (0x1610, ElfConstants.RArm64TlsLdAddDtprelLo12Nc, dtprelAddend),
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
