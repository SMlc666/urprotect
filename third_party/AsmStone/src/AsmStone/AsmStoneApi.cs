using AsmStone.Decode;
using AsmStone.Encode;
using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone;

public static class AsmStoneApi
{
    public static bool TryDecode(
        uint encoding,
        ulong address,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecode(encoding, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecode(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecode(encoding, address, features, out instruction, out diagnostic);
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> bytes,
        ulong address,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecode(bytes, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecode(
        ReadOnlySpan<byte> bytes,
        ulong address,
        A64FeatureSet features,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecode(bytes, address, features, out instruction, out diagnostic);
    }

    public static bool TryDecodeRaw(
        uint encoding,
        ulong address,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeRaw(encoding, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecodeRaw(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeRaw(encoding, address, features, out instruction, out diagnostic);
    }

    public static bool TryDecodeView(
        uint encoding,
        ulong address,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeView(encoding, address, operands, out instruction, out diagnostic);
    }

    public static bool TryDecodeView(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeView(
            encoding,
            address,
            features,
            operands,
            out instruction,
            out diagnostic);
    }

    public static bool TryDecodeRaw(
        ReadOnlySpan<byte> bytes,
        ulong address,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeRaw(bytes, address, A64FeatureSet.All, out instruction, out diagnostic);
    }

    public static bool TryDecodeRaw(
        ReadOnlySpan<byte> bytes,
        ulong address,
        A64FeatureSet features,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeRaw(bytes, address, features, out instruction, out diagnostic);
    }

    public static bool TryDecodeView(
        ReadOnlySpan<byte> bytes,
        ulong address,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeView(bytes, address, operands, out instruction, out diagnostic);
    }

    public static bool TryDecodeView(
        ReadOnlySpan<byte> bytes,
        ulong address,
        A64FeatureSet features,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        return A64Decoder.TryDecodeView(
            bytes,
            address,
            features,
            operands,
            out instruction,
            out diagnostic);
    }

    public static bool TryEncode(
        A64Instruction instruction,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64Encoder.TryEncode(instruction, A64FeatureSet.All, out encoding, out diagnostic);
    }

    public static bool TryEncode(
        A64Instruction instruction,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64Encoder.TryEncode(instruction, features, out encoding, out diagnostic);
    }

    public static bool TryEncode(
        A64Instruction instruction,
        Span<byte> destination,
        A64FeatureSet features,
        out A64Diagnostic diagnostic)
    {
        return A64Encoder.TryEncode(instruction, destination, features, out diagnostic);
    }

    public static bool TryEncode(
        A64Instruction instruction,
        Span<byte> destination,
        out A64Diagnostic diagnostic)
    {
        return A64Encoder.TryEncode(instruction, destination, out diagnostic);
    }

    public static bool TryEncodeFields(
        string name,
        IReadOnlyDictionary<string, uint> fields,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64InstructionCatalog.TryEncodeFields(name, fields, features, out encoding, out diagnostic);
    }

    public static bool TryEncodeFields(
        string name,
        ReadOnlySpan<A64FieldValue> fields,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64InstructionCatalog.TryEncodeFields(name, fields, features, out encoding, out diagnostic);
    }

    public static bool TryEncodeFields(
        string name,
        IReadOnlyDictionary<string, uint> fields,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64InstructionCatalog.TryEncodeFields(name, fields, out encoding, out diagnostic);
    }

    public static bool TryEncodeFields(
        string name,
        ReadOnlySpan<A64FieldValue> fields,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64InstructionCatalog.TryEncodeFields(name, fields, out encoding, out diagnostic);
    }

    public static bool TryEncodeFields(
        string name,
        IReadOnlyDictionary<string, uint> fields,
        Span<byte> destination,
        A64FeatureSet features,
        out A64Diagnostic diagnostic)
    {
        if (destination.Length < sizeof(uint))
        {
            diagnostic = new A64Diagnostic(
                A64DiagnosticCode.BufferTooSmall,
                "A64 instructions require four destination bytes.");
            return false;
        }

        if (!A64InstructionCatalog.TryEncodeFields(name, fields, features, out var encoding, out diagnostic))
        {
            return false;
        }

        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination, encoding);
        return true;
    }

    public static bool TryEncodeFields(
        string name,
        IReadOnlyDictionary<string, uint> fields,
        Span<byte> destination,
        out A64Diagnostic diagnostic)
    {
        return TryEncodeFields(name, fields, destination, A64FeatureSet.All, out diagnostic);
    }
}
