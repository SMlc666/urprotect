using System.Buffers.Binary;
using AsmStone.Model;

namespace AsmStone.Encode;

public static class A64Encoder
{
    public static bool TryEncode(
        A64Instruction instruction,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return TryEncode(instruction, A64FeatureSet.All, out encoding, out diagnostic);
    }

    public static bool TryEncode(
        A64Instruction instruction,
        A64FeatureSet features,
        out uint encoding,
        out A64Diagnostic diagnostic)
    {
        return A64GeneratedEncoder.TryEncode(instruction, features, out encoding, out diagnostic);
    }

    public static bool TryEncode(
        A64Instruction instruction,
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

        if (!TryEncode(instruction, features, out var encoding, out diagnostic))
        {
            return false;
        }

        BinaryPrimitives.WriteUInt32LittleEndian(destination, encoding);
        return true;
    }

    public static bool TryEncode(
        A64Instruction instruction,
        Span<byte> destination,
        out A64Diagnostic diagnostic)
    {
        return TryEncode(instruction, destination, A64FeatureSet.All, out diagnostic);
    }
}
