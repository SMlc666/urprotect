using A64DiagnosticCode = global::AsmStone.Model.A64DiagnosticCode;
using A64FeatureSet = global::AsmStone.Model.A64FeatureSet;
using A64InstructionFlags = global::AsmStone.Model.A64InstructionFlags;
using A64TargetOperand = global::AsmStone.Model.TargetOperand;

namespace UrProtect.Core.Aarch64;

[Flags]
public enum Aarch64InstructionProperties
{
    None = 0,
    Branch = 1 << 0,
    Call = 1 << 1,
    Return = 1 << 2,
    PcRelative = 1 << 3,
    Load = 1 << 4,
    Store = 1 << 5,
    Terminator = 1 << 6,
    SideEffects = 1 << 7,
}

public enum Aarch64DecodeStatus
{
    Decoded,
    UnknownEncoding,
    UnsupportedFeature,
    BackendUnavailable,
}

public enum Aarch64ControlFlowKind
{
    None,
    DirectBranch,
    DirectCall,
    ConditionalBranch,
    IndirectBranch,
    Return,
}

public sealed record Aarch64Instruction(
    ulong Address,
    uint Encoding,
    string SourceName,
    Aarch64InstructionProperties Properties,
    Aarch64ControlFlowKind ControlFlow,
    ulong? DirectTarget);

public readonly record struct Aarch64DecodeResult(
    Aarch64DecodeStatus Status,
    Aarch64Instruction? Instruction,
    string Diagnostic)
{
    public bool IsSuccess => Status == Aarch64DecodeStatus.Decoded && Instruction is not null;

    public static Aarch64DecodeResult BackendUnavailable(uint encoding, ulong address) =>
        new(
            Aarch64DecodeStatus.BackendUnavailable,
            null,
            $"No AArch64 decoder backend is configured for 0x{encoding:X8} at 0x{address:X}.");
}

public interface IAarch64Decoder
{
    Aarch64DecodeResult Decode(uint encoding, ulong address);
}

public sealed class AsmStoneAdapter : IAarch64Decoder
{
    private readonly A64FeatureSet features;
    private readonly Func<uint, ulong, Aarch64DecodeResult>? testDecoder;

    public AsmStoneAdapter()
        : this(A64FeatureSet.All, null)
    {
    }

    public AsmStoneAdapter(Func<uint, ulong, Aarch64DecodeResult> testDecoder)
        : this(A64FeatureSet.All, testDecoder)
    {
    }

    public AsmStoneAdapter(A64FeatureSet features)
        : this(features, null)
    {
    }

    private AsmStoneAdapter(
        A64FeatureSet features,
        Func<uint, ulong, Aarch64DecodeResult>? testDecoder)
    {
        this.features = features ?? throw new ArgumentNullException(nameof(features));
        this.testDecoder = testDecoder;
    }

    public Aarch64DecodeResult Decode(uint encoding, ulong address)
    {
        if (testDecoder is not null)
        {
            return testDecoder(encoding, address);
        }

        if (global::AsmStone.AsmStoneApi.TryDecode(
                encoding,
                address,
                features,
                out var instruction,
                out var diagnostic))
        {
            return new Aarch64DecodeResult(
                Aarch64DecodeStatus.Decoded,
                CreateInstruction(instruction),
                diagnostic.Message);
        }

        var status = diagnostic.Code == A64DiagnosticCode.UnsupportedFeature
            ? Aarch64DecodeStatus.UnsupportedFeature
            : Aarch64DecodeStatus.UnknownEncoding;
        return new Aarch64DecodeResult(status, null, diagnostic.ToString());
    }

    private static Aarch64Instruction CreateInstruction(global::AsmStone.Model.A64Instruction instruction)
    {
        var properties = Aarch64InstructionProperties.None;
        var flags = instruction.Flags;
        if (flags.HasFlag(A64InstructionFlags.IsBranch))
        {
            properties |= Aarch64InstructionProperties.Branch;
        }

        if (flags.HasFlag(A64InstructionFlags.IsCall))
        {
            properties |= Aarch64InstructionProperties.Call;
        }

        if (flags.HasFlag(A64InstructionFlags.IsReturn))
        {
            properties |= Aarch64InstructionProperties.Return;
        }

        if (flags.HasFlag(A64InstructionFlags.IsPcRelative))
        {
            properties |= Aarch64InstructionProperties.PcRelative;
        }

        if (flags.HasFlag(A64InstructionFlags.IsLoad))
        {
            properties |= Aarch64InstructionProperties.Load;
        }

        if (flags.HasFlag(A64InstructionFlags.IsStore))
        {
            properties |= Aarch64InstructionProperties.Store;
        }

        if (flags.HasFlag(A64InstructionFlags.IsTerminator))
        {
            properties |= Aarch64InstructionProperties.Terminator;
        }

        if (flags.HasFlag(A64InstructionFlags.HasSideEffects))
        {
            properties |= Aarch64InstructionProperties.SideEffects;
        }

        var target = instruction.Operands
            .OfType<A64TargetOperand>()
            .Select(operand => (ulong?)operand.Address)
            .FirstOrDefault();
        var controlFlow = ClassifyControlFlow(instruction, target);
        return new Aarch64Instruction(
            instruction.Address,
            instruction.Encoding,
            instruction.SourceName ?? instruction.Mnemonic,
            properties,
            controlFlow,
            target);
    }

    private static Aarch64ControlFlowKind ClassifyControlFlow(
        global::AsmStone.Model.A64Instruction instruction,
        ulong? target)
    {
        var flags = instruction.Flags;
        if (flags.HasFlag(A64InstructionFlags.IsReturn))
        {
            return Aarch64ControlFlowKind.Return;
        }

        if (!flags.HasFlag(A64InstructionFlags.IsBranch))
        {
            return Aarch64ControlFlowKind.None;
        }

        if (flags.HasFlag(A64InstructionFlags.IsCall))
        {
            return target.HasValue
                ? Aarch64ControlFlowKind.DirectCall
                : Aarch64ControlFlowKind.IndirectBranch;
        }

        return IsConditionalMnemonic(instruction.Mnemonic)
            ? Aarch64ControlFlowKind.ConditionalBranch
            : target.HasValue
                ? Aarch64ControlFlowKind.DirectBranch
                : Aarch64ControlFlowKind.IndirectBranch;
    }

    private static bool IsConditionalMnemonic(string mnemonic)
    {
        return mnemonic.StartsWith("b.", StringComparison.OrdinalIgnoreCase)
            || mnemonic.StartsWith("cb", StringComparison.OrdinalIgnoreCase)
            || mnemonic.StartsWith("tb", StringComparison.OrdinalIgnoreCase);
    }
}
