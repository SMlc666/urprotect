using System.Buffers.Binary;
using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Decode;

public static class A64Decoder
{
    public static bool TryDecode(
        uint encoding,
        ulong address,
        out A64Instruction instruction)
    {
        return TryDecode(encoding, address, A64FeatureSet.All, out instruction, out _);
    }

    public static bool TryDecode(
        uint encoding,
        ulong address,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        return TryDecode(encoding, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecode(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(features);
        return A64GeneratedDecode.TryDecode(encoding, address, features, out instruction, out diagnostic);
    }

    public static bool TryDecode(
        uint encoding,
        ulong address,
        A64Feature features,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        return TryDecode(encoding, address, A64FeatureSet.From(features), out instruction, out diagnostic);
    }

    public static bool TryDecodeRaw(
        uint encoding,
        ulong address,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        return TryDecodeRaw(encoding, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecodeRaw(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(features);
        return A64GeneratedDecode.TryDecodeRaw(encoding, address, features, out instruction, out diagnostic);
    }

    public static bool TryDecodeView(
        uint encoding,
        ulong address,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        return TryDecodeView(
            encoding,
            address,
            A64FeatureSet.All,
            operands,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecodeView(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        ArgumentNullException.ThrowIfNull(features);
        return A64GeneratedDecode.TryDecodeView(
            encoding,
            address,
            features,
            operands,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> bytes,
        ulong address,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        if (bytes.Length < sizeof(uint))
        {
            instruction = new A64Instruction(
                A64InstructionId.Unknown,
                ".word",
                Array.Empty<A64Operand>(),
                0,
                address);
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.BufferTooSmall,
                "A64 instructions require four bytes.");
            return false;
        }

        return TryDecode(
            BinaryPrimitives.ReadUInt32LittleEndian(bytes),
            address,
            A64FeatureSet.All,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecodeRaw(
        ReadOnlySpan<byte> bytes,
        ulong address,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        return TryDecodeRaw(bytes, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecodeRaw(
        ReadOnlySpan<byte> bytes,
        ulong address,
        A64FeatureSet features,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        if (bytes.Length < sizeof(uint))
        {
            instruction = default;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.BufferTooSmall,
                "A64 instructions require four bytes.");
            return false;
        }

        return TryDecodeRaw(
            BinaryPrimitives.ReadUInt32LittleEndian(bytes),
            address,
            features,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecodeView(
        ReadOnlySpan<byte> bytes,
        ulong address,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        return TryDecodeView(
            bytes,
            address,
            A64FeatureSet.All,
            operands,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecodeView(
        ReadOnlySpan<byte> bytes,
        ulong address,
        A64FeatureSet features,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        if (bytes.Length < sizeof(uint))
        {
            instruction = default;
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.BufferTooSmall,
                "A64 instructions require four bytes.");
            return false;
        }

        return TryDecodeView(
            BinaryPrimitives.ReadUInt32LittleEndian(bytes),
            address,
            features,
            operands,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> bytes,
        ulong address,
        A64FeatureSet features,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        if (bytes.Length < sizeof(uint))
        {
            instruction = new A64Instruction(
                A64InstructionId.Unknown,
                ".word",
                Array.Empty<A64Operand>(),
                0,
                address);
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.BufferTooSmall,
                "A64 instructions require four bytes.");
            return false;
        }

        return TryDecode(
            BinaryPrimitives.ReadUInt32LittleEndian(bytes),
            address,
            features,
            out instruction,
            out diagnostic);
    }

}
