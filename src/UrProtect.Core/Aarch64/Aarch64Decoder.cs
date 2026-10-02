using A64DiagnosticCode = global::AsmStone.Model.A64DiagnosticCode;
using A64FeatureSet = global::AsmStone.Model.A64FeatureSet;
using A64InstructionFlags = global::AsmStone.Model.A64InstructionFlags;
using A64Operand = global::AsmStone.Model.A64Operand;
using A64Register = global::AsmStone.Model.A64Register;
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
    ReadsNzcv = 1 << 8,
    WritesNzcv = 1 << 9,
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

public enum Aarch64OperandKind
{
    Unknown,
    Register,
    RegisterPair,
    RegisterList,
    Memory,
    Immediate,
    Target,
    EncodedField,
}

public enum Aarch64OperandDirection
{
    Input,
    Output,
    InputOutput,
}

public enum Aarch64RegisterClass
{
    General,
    Vector,
    FloatingPoint,
    SveVector,
    Predicate,
    System,
    Special,
}

public enum Aarch64RegisterRole
{
    None,
    StackPointer,
    Zero,
}

public readonly record struct Aarch64RegisterView(
    Aarch64RegisterClass Class,
    byte Index,
    byte Width,
    Aarch64RegisterRole Role);

public readonly record struct Aarch64RegisterConstraint(
    int MinimumIndex,
    int MaximumIndex,
    int Step,
    uint AllowedMask);

public sealed record Aarch64MemoryReference(
    Aarch64RegisterView Base,
    Aarch64RegisterView? Index,
    long Offset,
    string AddressingMode,
    uint? IndexModifier,
    int AccessSize,
    string Ordering,
    bool WritesBack);

public sealed record Aarch64SemanticOperand(
    string Name,
    Aarch64OperandKind Kind,
    Aarch64OperandDirection Direction,
    bool IsImplicit,
    string Codec,
    string? TiedTo,
    Aarch64RegisterView? Register,
    IReadOnlyList<Aarch64RegisterView> Registers,
    Aarch64MemoryReference? Memory,
    long? Immediate,
    ulong? Target,
    Aarch64RegisterConstraint RegisterConstraint,
    int RegisterWidth,
    int FieldWidth,
    int ElementWidth,
    bool AllowsStackPointer,
    bool AllowsZeroRegister,
    bool IsPageRelative,
    string SemanticDomain);

public sealed record Aarch64Instruction(
    ulong Address,
    uint Encoding,
    string SourceName,
    Aarch64InstructionProperties Properties,
    Aarch64ControlFlowKind ControlFlow,
    ulong? DirectTarget)
{
    public IReadOnlyList<Aarch64SemanticOperand> Operands { get; init; } =
        Array.Empty<Aarch64SemanticOperand>();
}

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

public readonly record struct Aarch64EncodeResult(
    bool IsSuccess,
    uint Encoding,
    string Diagnostic);

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

    public Aarch64EncodeResult TryPermuteGeneralRegisters(
        uint encoding,
        ulong address,
        IReadOnlyDictionary<byte, byte> mapping)
    {
        ArgumentNullException.ThrowIfNull(mapping);
        if (!global::AsmStone.AsmStoneApi.TryDecode(
                encoding,
                address,
                features,
                out var instruction,
                out var decodeDiagnostic))
        {
            return new Aarch64EncodeResult(false, 0, decodeDiagnostic.ToString());
        }

        var mappedOperands = instruction.Operands
            .Select(operand => MapGeneralRegisters(operand, mapping))
            .ToArray();
        var mappedInstruction = instruction with { Operands = mappedOperands };
        if (!global::AsmStone.AsmStoneApi.TryEncode(
                mappedInstruction,
                features,
                out var mappedEncoding,
                out var encodeDiagnostic))
        {
            return new Aarch64EncodeResult(false, 0, encodeDiagnostic.ToString());
        }

        if (!global::AsmStone.AsmStoneApi.TryDecode(
                mappedEncoding,
                address,
                features,
                out var roundTrip,
                out var roundTripDiagnostic)
            || !string.Equals(
                roundTrip.Mnemonic,
                instruction.Mnemonic,
                StringComparison.OrdinalIgnoreCase))
        {
            return new Aarch64EncodeResult(
                false,
                0,
                $"AsmStone register permutation did not round-trip: {roundTripDiagnostic}");
        }

        return new Aarch64EncodeResult(true, mappedEncoding, encodeDiagnostic.Message);
    }

    public bool UsesGeneralRegister(uint encoding, ulong address, byte registerIndex)
    {
        if (!global::AsmStone.AsmStoneApi.TryDecode(
                encoding,
                address,
                features,
                out var instruction,
                out _))
        {
            return false;
        }

        return instruction.Operands.Any(operand => ContainsGeneralRegister(operand, registerIndex))
            || instruction.OperandSemantics
                .Select(operand => operand.Operand)
                .Where(operand => operand is not null)
                .Any(operand => ContainsGeneralRegister(operand!, registerIndex));
    }

    private static A64Operand MapGeneralRegisters(
        A64Operand operand,
        IReadOnlyDictionary<byte, byte> mapping)
    {
        return operand switch
        {
            global::AsmStone.Model.RegisterOperand register =>
                register with { Register = MapGeneralRegister(register.Register, mapping) },
            global::AsmStone.Model.ModifiedRegisterOperand modified =>
                modified with { Register = MapGeneralRegister(modified.Register, mapping) },
            global::AsmStone.Model.RegisterPairOperand pair =>
                pair with
                {
                    First = MapGeneralRegister(pair.First, mapping),
                    Second = MapGeneralRegister(pair.Second, mapping),
                },
            global::AsmStone.Model.VectorRegisterListOperand list =>
                list with
                {
                    Registers = list.Registers
                        .Select(register => MapGeneralRegister(register, mapping))
                        .ToArray(),
                },
            global::AsmStone.Model.RegisterGroupOperand group =>
                group with
                {
                    Registers = group.Registers
                        .Select(register => MapGeneralRegister(register, mapping))
                        .ToArray(),
                },
            global::AsmStone.Model.MemoryOperand memory =>
                memory with
                {
                    Base = MapGeneralRegister(memory.Base, mapping),
                    Index = memory.Index is { } index
                        ? MapGeneralRegister(index, mapping)
                        : null,
                },
            _ => operand,
        };
    }

    private static bool ContainsGeneralRegister(A64Operand operand, byte index)
    {
        return operand switch
        {
            global::AsmStone.Model.RegisterOperand register =>
                register.Register.Class == global::AsmStone.Model.A64RegisterClass.General
                && register.Register.Role == global::AsmStone.Model.A64RegisterRole.None
                && register.Register.Index == index,
            global::AsmStone.Model.ModifiedRegisterOperand modified =>
                modified.Register.Class == global::AsmStone.Model.A64RegisterClass.General
                && modified.Register.Role == global::AsmStone.Model.A64RegisterRole.None
                && modified.Register.Index == index,
            global::AsmStone.Model.RegisterPairOperand pair =>
                ContainsGeneralRegister(pair.First, index)
                || ContainsGeneralRegister(pair.Second, index),
            global::AsmStone.Model.VectorRegisterListOperand list =>
                list.Registers.Any(register => ContainsGeneralRegister(register, index)),
            global::AsmStone.Model.RegisterGroupOperand group =>
                group.Registers.Any(register => ContainsGeneralRegister(register, index)),
            global::AsmStone.Model.MemoryOperand memory =>
                ContainsGeneralRegister(memory.Base, index)
                || (memory.Index is { } memoryIndex && ContainsGeneralRegister(memoryIndex, index)),
            _ => false,
        };
    }

    private static bool ContainsGeneralRegister(A64Register register, byte index) =>
        register.Class == global::AsmStone.Model.A64RegisterClass.General
        && register.Role == global::AsmStone.Model.A64RegisterRole.None
        && register.Index == index;

    private static A64Register MapGeneralRegister(
        A64Register register,
        IReadOnlyDictionary<byte, byte> mapping)
    {
        if (register.Class != global::AsmStone.Model.A64RegisterClass.General
            || register.Role != global::AsmStone.Model.A64RegisterRole.None
            || !mapping.TryGetValue(register.Index, out var mappedIndex))
        {
            return register;
        }

        return register with { Index = mappedIndex };
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

        if (flags.HasFlag(A64InstructionFlags.ReadsNzcv))
        {
            properties |= Aarch64InstructionProperties.ReadsNzcv;
        }

        if (flags.HasFlag(A64InstructionFlags.WritesNzcv))
        {
            properties |= Aarch64InstructionProperties.WritesNzcv;
        }

        var target = instruction.Operands
            .OfType<A64TargetOperand>()
            .Select(operand => (ulong?)operand.Address)
            .FirstOrDefault();
        var controlFlow = ClassifyControlFlow(instruction, target);
        var projectInstruction = new Aarch64Instruction(
            instruction.Address,
            instruction.Encoding,
            instruction.SourceName ?? instruction.Mnemonic,
            properties,
            controlFlow,
            target);
        return projectInstruction with
        {
            Operands = instruction.OperandSemantics
                .Select(MapSemanticOperand)
                .ToArray(),
        };
    }

    private static Aarch64SemanticOperand MapSemanticOperand(
        global::AsmStone.Model.A64InstructionOperand operand)
    {
        var mapped = MapOperand(operand.Operand, out var register, out var registers, out var memory, out var immediate, out var target);
        return new Aarch64SemanticOperand(
            operand.Name,
            mapped,
            operand.Direction switch
            {
                global::AsmStone.Model.A64OperandDirection.Output => Aarch64OperandDirection.Output,
                global::AsmStone.Model.A64OperandDirection.InputOutput => Aarch64OperandDirection.InputOutput,
                _ => Aarch64OperandDirection.Input,
            },
            operand.IsImplicit,
            operand.Codec,
            operand.TiedTo,
            register,
            registers,
            memory,
            immediate,
            target,
            new Aarch64RegisterConstraint(
                operand.RegisterConstraint.MinimumIndex,
                operand.RegisterConstraint.MaximumIndex,
                operand.RegisterConstraint.Step,
                operand.RegisterConstraint.AllowedMask),
            operand.RegisterWidth,
            operand.FieldWidth,
            operand.ElementWidth,
            operand.AllowsStackPointer,
            operand.AllowsZeroRegister,
            operand.IsPageRelative,
            operand.SemanticDomain);
    }

    private static Aarch64OperandKind MapOperand(
        global::AsmStone.Model.A64Operand? operand,
        out Aarch64RegisterView? register,
        out IReadOnlyList<Aarch64RegisterView> registers,
        out Aarch64MemoryReference? memory,
        out long? immediate,
        out ulong? target)
    {
        register = null;
        registers = Array.Empty<Aarch64RegisterView>();
        memory = null;
        immediate = null;
        target = null;
        switch (operand)
        {
            case global::AsmStone.Model.RegisterOperand value:
                register = MapRegister(value.Register);
                return Aarch64OperandKind.Register;
            case global::AsmStone.Model.ModifiedRegisterOperand value:
                register = MapRegister(value.Register);
                return Aarch64OperandKind.Register;
            case global::AsmStone.Model.RegisterPairOperand value:
                registers = new[] { MapRegister(value.First), MapRegister(value.Second) };
                return Aarch64OperandKind.RegisterPair;
            case global::AsmStone.Model.VectorRegisterListOperand value:
                registers = value.Registers.Select(MapRegister).ToArray();
                return Aarch64OperandKind.RegisterList;
            case global::AsmStone.Model.RegisterGroupOperand value:
                registers = value.Registers.Select(MapRegister).ToArray();
                return Aarch64OperandKind.RegisterList;
            case global::AsmStone.Model.MemoryOperand value:
                memory = new Aarch64MemoryReference(
                    MapRegister(value.Base),
                    value.Index is { } index ? MapRegister(index) : null,
                    value.Offset,
                    value.Mode.ToString(),
                    value.IndexModifier,
                    value.AccessSize,
                    value.Ordering.ToString(),
                    value.WritesBack);
                return Aarch64OperandKind.Memory;
            case global::AsmStone.Model.TargetOperand value:
                target = value.Address;
                return Aarch64OperandKind.Target;
            case global::AsmStone.Model.ImmediateOperand value:
                immediate = value.Value;
                return Aarch64OperandKind.Immediate;
            case global::AsmStone.Model.FloatingImmediateOperand:
                return Aarch64OperandKind.Immediate;
            case null:
                return Aarch64OperandKind.Unknown;
            default:
                return Aarch64OperandKind.EncodedField;
        }
    }

    private static Aarch64RegisterView MapRegister(global::AsmStone.Model.A64Register register) =>
        new(
            register.Class switch
            {
                global::AsmStone.Model.A64RegisterClass.General => Aarch64RegisterClass.General,
                global::AsmStone.Model.A64RegisterClass.Vector => Aarch64RegisterClass.Vector,
                global::AsmStone.Model.A64RegisterClass.FloatingPoint => Aarch64RegisterClass.FloatingPoint,
                global::AsmStone.Model.A64RegisterClass.SveVector => Aarch64RegisterClass.SveVector,
                global::AsmStone.Model.A64RegisterClass.Predicate => Aarch64RegisterClass.Predicate,
                global::AsmStone.Model.A64RegisterClass.System => Aarch64RegisterClass.System,
                _ => Aarch64RegisterClass.Special,
            },
            register.Index,
            register.Width,
            register.Role switch
            {
                global::AsmStone.Model.A64RegisterRole.StackPointer => Aarch64RegisterRole.StackPointer,
                global::AsmStone.Model.A64RegisterRole.Zero => Aarch64RegisterRole.Zero,
                _ => Aarch64RegisterRole.None,
            });

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
