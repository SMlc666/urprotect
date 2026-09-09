using AsmStone.Generated;
using AsmStone.Model;

namespace AsmStone.Decode;

internal static class A64GeneratedDecode
{
    public static bool TryDecodeView(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        Span<A64OperandView> operands,
        out A64InstructionView instruction,
        out A64Diagnostic diagnostic)
    {
        if (!A64InstructionCatalog.TryFindCompiled(encoding, features, out var decoded))
        {
            instruction = default;
            diagnostic = A64InstructionCatalog.TryFindUnsupported(encoding, features, out _)
                ? new A64Diagnostic(
                    A64DiagnosticCode.UnsupportedFeature,
                    "The instruction requires a feature outside the selected profile.")
                : new A64Diagnostic(
                    A64DiagnosticCode.UnknownEncoding,
                    "The instruction encoding is not recognized.");
            return false;
        }

        if (!A64OperandViewMaterializer.TryMaterialize(
                decoded,
                encoding,
                address,
                operands,
                out var operandCount,
                out diagnostic))
        {
            instruction = default;
            return false;
        }

        instruction = new A64InstructionView(
            decoded,
            encoding,
            address,
            operands[..operandCount]);
        diagnostic = A64Diagnostic.None;
        return true;
    }

    public static bool TryDecodeRaw(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        out A64RawInstruction instruction,
        out A64Diagnostic diagnostic)
    {
        if (A64InstructionCatalog.TryFindCompiled(encoding, features, out var decoded))
        {
            instruction = new A64RawInstruction(decoded, encoding, address);
            diagnostic = A64Diagnostic.None;
            return true;
        }

        instruction = default;
        diagnostic = A64InstructionCatalog.TryFindUnsupported(encoding, features, out _)
            ? new A64Diagnostic(
                A64DiagnosticCode.UnsupportedFeature,
                "The instruction requires a feature outside the selected profile.")
            : new A64Diagnostic(
                A64DiagnosticCode.UnknownEncoding,
                "The instruction encoding is not recognized.");
        return false;
    }

    public static bool TryDecode(
        uint encoding,
        ulong address,
        A64FeatureSet features,
        out A64Instruction instruction,
        out A64Diagnostic diagnostic)
    {
        if (A64InstructionCatalog.TryFindCompiled(encoding, features, out var decoded))
        {
            var operands = decoded.OperandCount == 0
                ? Array.Empty<A64Operand>()
                : A64OperandMaterializer.Materialize(decoded, encoding, address);
            var flags = decoded.Info.Flags;
            var ordering = A64GeneratedMemory.Ordering(decoded);
            if (ordering is A64MemoryOrdering.Acquire or A64MemoryOrdering.AcquireRelease)
            {
                flags |= A64InstructionFlags.IsAcquire;
            }

            if (ordering is A64MemoryOrdering.Release or A64MemoryOrdering.AcquireRelease)
            {
                flags |= A64InstructionFlags.IsRelease;
            }

            instruction = new A64Instruction(
                A64InstructionId.Generated,
                decoded.Info.Mnemonic,
                operands,
                encoding,
                address)
            {
                SourceName = decoded.Info.Name,
                Flags = flags
                    | (HasPcRelativeOperand(decoded)
                        ? A64InstructionFlags.IsPcRelative
                        : A64InstructionFlags.None),
            };
            diagnostic = A64Diagnostic.None;
            return true;
        }

        instruction = new A64Instruction(
            A64InstructionId.Unknown,
            ".word",
            new A64Operand[] { new ImmediateOperand(unchecked((int)encoding)) },
            encoding,
            address);
        diagnostic = A64InstructionCatalog.TryFindUnsupported(encoding, features, out var unsupported)
            ? new A64Diagnostic(
                A64DiagnosticCode.UnsupportedFeature,
                $"Generated instruction '{unsupported.Name}' requires predicates: {unsupported.Predicates}.")
            : new A64Diagnostic(
                A64DiagnosticCode.UnknownEncoding,
                $"No generated A64 decoder matched 0x{encoding:X8}.");
        return false;
    }

    private static bool HasPcRelativeOperand(A64CompiledInstruction instruction)
    {
        foreach (var binding in instruction.Bindings)
        {
            if (binding.Codec?.OperandType == "OPERAND_PCREL")
            {
                return true;
            }
        }

        return false;
    }
}
