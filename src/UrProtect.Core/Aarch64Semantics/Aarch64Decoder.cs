using A64DiagnosticCode = global::AsmStone.Model.A64DiagnosticCode;
using A64FeatureSet = global::AsmStone.Model.A64FeatureSet;
using A64InstructionFlags = global::AsmStone.Model.A64InstructionFlags;
using A64Operand = global::AsmStone.Model.A64Operand;
using A64Register = global::AsmStone.Model.A64Register;

namespace UrProtect.Core.Aarch64Semantics;

public enum Aarch64MemoryEffect
{
    None,
    Read,
    PlainWrite,
    ReadModifyWrite,
    ConditionalWrite,
    // Includes implicit/address-bearing accesses whose backend reports memory
    // or side effects but provides no explicit project-owned Memory operand.
    Unclassified,
}

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
    bool WritesBack,
    string? IndexModifierKind = null,
    int IndexModifierAmount = 0);

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
    string SemanticDomain)
{
    public string? RegisterModifierKind { get; init; }

    public int RegisterModifierAmount { get; init; }
}

public sealed record Aarch64Instruction(
    ulong Address,
    uint Encoding,
    string SourceName,
    Aarch64InstructionProperties Properties,
    Aarch64ControlFlowKind ControlFlow,
    ulong? DirectTarget)
{
    public string Mnemonic { get; init; } = SourceName;

    public Aarch64MemoryEffect MemoryEffect { get; init; } = Aarch64MemoryEffect.None;

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

    internal AsmStoneAdapter(A64FeatureSet features)
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
            if (TryCreateInstruction(instruction, out var projectedInstruction, out var projectionDiagnostic))
            {
                return new Aarch64DecodeResult(
                    Aarch64DecodeStatus.Decoded,
                    projectedInstruction,
                    diagnostic.Message);
            }

            return new Aarch64DecodeResult(
                Aarch64DecodeStatus.UnknownEncoding,
                null,
                projectionDiagnostic);
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
        return new Aarch64InstructionEncoder(features)
            .TryPermuteGeneralRegisters(encoding, address, mapping);
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

    private static bool TryCreateInstruction(
        global::AsmStone.Model.A64Instruction instruction,
        out Aarch64Instruction projectedInstruction,
        out string diagnostic)
    {
        projectedInstruction = null!;
        diagnostic = string.Empty;

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

        var operands = new Aarch64SemanticOperand[instruction.OperandSemantics.Count];
        for (var index = 0; index < operands.Length; index++)
        {
            if (!TryMapSemanticOperand(
                    instruction.OperandSemantics[index],
                    instruction.Address,
                    out operands[index],
                    out diagnostic))
            {
                return false;
            }
        }

        var target = operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Target)
            .Select(operand => operand.Target)
            .FirstOrDefault();
        var controlFlow = ClassifyControlFlow(instruction, target);
        var memoryEffect = ClassifyMemoryEffect(instruction.Mnemonic, flags, operands, out var projectedAccessSize);
        if (projectedAccessSize is { } accessSize)
        {
            var memoryOperandIndex = Array.FindIndex(operands, operand => operand.Memory is not null);
            if (memoryOperandIndex >= 0)
            {
                var memoryOperand = operands[memoryOperandIndex];
                operands[memoryOperandIndex] = memoryOperand with
                {
                    Memory = memoryOperand.Memory! with { AccessSize = accessSize },
                };
            }
        }

        projectedInstruction = new Aarch64Instruction(
            instruction.Address,
            instruction.Encoding,
            instruction.SourceName ?? instruction.Mnemonic,
            properties,
            controlFlow,
            target)
        {
            Mnemonic = instruction.Mnemonic,
            MemoryEffect = memoryEffect,
            Operands = operands,
        };
        return true;
    }

    private static Aarch64MemoryEffect ClassifyMemoryEffect(
        string mnemonic,
        A64InstructionFlags flags,
        IReadOnlyList<Aarch64SemanticOperand> operands,
        out int? projectedAccessSize)
    {
        projectedAccessSize = null;
        var memoryOperands = operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Memory && operand.Memory is not null)
            .ToArray();
        if (memoryOperands.Length == 0)
        {
            return HasUnclassifiedImplicitMemoryEffect(mnemonic, flags, operands)
                ? Aarch64MemoryEffect.Unclassified
                : Aarch64MemoryEffect.None;
        }

        if (memoryOperands.Length != 1)
        {
            return Aarch64MemoryEffect.Unclassified;
        }

        var memoryOperand = memoryOperands[0];
        var memory = memoryOperand.Memory!;
        if (memory.AccessSize is <= 0 or > 16)
        {
            return Aarch64MemoryEffect.Unclassified;
        }

        var normalizedMnemonic = mnemonic.ToUpperInvariant();
        if (normalizedMnemonic.StartsWith("SWP", StringComparison.Ordinal))
        {
            if (!IsSwapMnemonic(normalizedMnemonic)
                || !TryGetSwapAccessSize(memoryOperand, operands, normalizedMnemonic, out var swapAccessSize))
            {
                return Aarch64MemoryEffect.Unclassified;
            }

            projectedAccessSize = swapAccessSize;
            return Aarch64MemoryEffect.ReadModifyWrite;
        }

        if (IsConditionalMemoryWriteMnemonic(normalizedMnemonic))
        {
            return HasValidConditionalMemoryWriteShape(memory, operands)
                ? Aarch64MemoryEffect.ConditionalWrite
                : Aarch64MemoryEffect.Unclassified;
        }

        var isLoad = flags.HasFlag(A64InstructionFlags.IsLoad);
        var isStore = flags.HasFlag(A64InstructionFlags.IsStore);
        if (isLoad && isStore)
        {
            return Aarch64MemoryEffect.ReadModifyWrite;
        }

        if (isLoad && IsProvenReadMnemonic(normalizedMnemonic))
        {
            return Aarch64MemoryEffect.Read;
        }

        if (isStore && IsPlainStoreMnemonic(normalizedMnemonic))
        {
            return Aarch64MemoryEffect.PlainWrite;
        }

        return Aarch64MemoryEffect.Unclassified;
    }

    private static bool HasUnclassifiedImplicitMemoryEffect(
        string mnemonic,
        A64InstructionFlags flags,
        IReadOnlyList<Aarch64SemanticOperand> operands)
    {
        if (flags.HasFlag(A64InstructionFlags.IsLoad)
            || flags.HasFlag(A64InstructionFlags.IsStore))
        {
            return true;
        }

        if (!flags.HasFlag(A64InstructionFlags.HasSideEffects))
        {
            return false;
        }

        // Barriers order memory operations but do not themselves write data.
        // MRS is also a read-only system-register operation; validate its
        // projected operand shape rather than treating all SYSTEM instructions
        // as harmless. Other side-effecting no-operand forms fail closed.
        if (flags.HasFlag(A64InstructionFlags.IsBarrier)
            || mnemonic.Equals("dmb", StringComparison.OrdinalIgnoreCase)
            || mnemonic.Equals("dsb", StringComparison.OrdinalIgnoreCase)
            || mnemonic.Equals("isb", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return !IsWellFormedSystemRegisterRead(mnemonic, flags, operands);
    }

    private static bool IsWellFormedSystemRegisterRead(
        string mnemonic,
        A64InstructionFlags flags,
        IReadOnlyList<Aarch64SemanticOperand> operands)
    {
        if (!flags.HasFlag(A64InstructionFlags.IsSystem)
            || !mnemonic.Equals("mrs", StringComparison.OrdinalIgnoreCase)
            || operands.Count != 2)
        {
            return false;
        }

        var output = operands[0];
        var systemRegister = operands[1];
        return output.Kind == Aarch64OperandKind.Register
            && output.Direction == Aarch64OperandDirection.Output
            && output.Register is { Class: Aarch64RegisterClass.General }
            && systemRegister.Kind == Aarch64OperandKind.EncodedField
            && systemRegister.Direction == Aarch64OperandDirection.Input;
    }

    private static bool IsSwapMnemonic(string mnemonic) => mnemonic is
        "SWP" or "SWPA" or "SWPL" or "SWPAL"
        or "SWPB" or "SWPAB" or "SWPLB" or "SWPALB"
        or "SWPH" or "SWPAH" or "SWPLH" or "SWPALH";

    private static bool TryGetSwapAccessSize(
        Aarch64SemanticOperand memoryOperand,
        IReadOnlyList<Aarch64SemanticOperand> operands,
        string mnemonic,
        out int accessSize)
    {
        accessSize = 0;
        var memory = memoryOperand.Memory!;
        var registerOperands = operands
            .Where(operand => operand.Kind == Aarch64OperandKind.Register
                && !operand.IsImplicit
                && operand.Register is { Class: Aarch64RegisterClass.General })
            .ToArray();
        var inputs = registerOperands.Where(operand => operand.Direction == Aarch64OperandDirection.Input).ToArray();
        var outputs = registerOperands.Where(operand => operand.Direction == Aarch64OperandDirection.Output).ToArray();
        if (memoryOperand.Direction != Aarch64OperandDirection.Input
            || memory.Base.Class != Aarch64RegisterClass.General
            || memory.Base.Width != 64
            || memory.Index is not null
            || memory.Offset != 0
            || memory.WritesBack
            || memory.IndexModifier is not null
            || !string.Equals(memory.AddressingMode, "Offset", StringComparison.Ordinal)
            || inputs.Length != 1
            || outputs.Length != 1)
        {
            return false;
        }

        var input = inputs[0].Register!.Value;
        var output = outputs[0].Register!.Value;
        if (input.Width is not (32 or 64) || output.Width != input.Width)
        {
            return false;
        }

        var byteAccess = mnemonic.EndsWith('B');
        var halfwordAccess = mnemonic.EndsWith('H');
        accessSize = byteAccess ? 1 : halfwordAccess ? 2 : input.Width / 8;
        if ((byteAccess || halfwordAccess) && input.Width != 32)
        {
            return false;
        }

        var backendWidth = input.Width / 8;
        return memory.AccessSize == backendWidth || memory.AccessSize == accessSize;
    }

    private static bool IsConditionalMemoryWriteMnemonic(string mnemonic) => mnemonic is
        "CAS" or "CASA" or "CASL" or "CASAL"
        or "CASB" or "CASAB" or "CASLB" or "CASALB"
        or "CASH" or "CASAH" or "CASLH" or "CASALH"
        or "CASP" or "CASPA" or "CASPL" or "CASPAL"
        or "STXR" or "STLXR" or "STXRB" or "STLXRB"
        or "STXRH" or "STLXRH" or "STXP" or "STLXP";

    private static bool HasValidConditionalMemoryWriteShape(
        Aarch64MemoryReference memory,
        IReadOnlyList<Aarch64SemanticOperand> operands)
    {
        var registers = operands
            .Where(operand =>
                (operand.Kind == Aarch64OperandKind.Register
                    && operand.Register is { Class: Aarch64RegisterClass.General })
                || (operand.Kind == Aarch64OperandKind.RegisterPair
                    && operand.Registers.Count > 0
                    && operand.Registers.All(register => register.Class == Aarch64RegisterClass.General)))
            .ToArray();
        return memory.Base.Class == Aarch64RegisterClass.General
            && memory.Base.Width == 64
            && memory.AccessSize is 1 or 2 or 4 or 8 or 16
            && memory.Index is null
            && memory.Offset == 0
            && !memory.WritesBack
            && registers.Any(operand => operand.Direction == Aarch64OperandDirection.Input)
            && registers.Any(operand => operand.Direction == Aarch64OperandDirection.Output);
    }

    private static bool IsProvenReadMnemonic(string mnemonic) => mnemonic is
        "LDR" or "LDRB" or "LDRH" or "LDRSB" or "LDRSH" or "LDRSW"
        or "LDUR" or "LDURB" or "LDURH" or "LDURSB" or "LDURSH" or "LDURSW"
        or "LDP" or "LDNP" or "LDPSW"
        or "LDTR" or "LDTRB" or "LDTRH" or "LDTRSB" or "LDTRSH" or "LDTRSW"
        or "LDAR" or "LDARB" or "LDARH"
        or "LDAPR" or "LDAPRB" or "LDAPRH"
        or "LDXR" or "LDXRB" or "LDXRH" or "LDXP"
        or "LDAXR" or "LDAXRB" or "LDAXRH" or "LDAXP";

    private static bool IsPlainStoreMnemonic(string mnemonic) => mnemonic is
        "STR" or "STRB" or "STRH"
        or "STUR" or "STURB" or "STURH"
        or "STP" or "STNP"
        or "STLR" or "STLRB" or "STLRH"
        or "STLUR" or "STLURB" or "STLURH";

    private static bool TryMapSemanticOperand(
        global::AsmStone.Model.A64InstructionOperand operand,
        ulong instructionAddress,
        out Aarch64SemanticOperand mappedOperand,
        out string diagnostic)
    {
        var mapped = MapOperand(
            operand.Operand,
            out var register,
            out var registers,
            out var memory,
            out var immediate,
            out var target,
            out var registerModifierKind,
            out var registerModifierAmount);
        diagnostic = string.Empty;
        if (operand.IsPageRelative)
        {
            if (mapped != Aarch64OperandKind.Target
                || target is not { } pageRelativeTarget
                || !TryNormalizePageRelativeTarget(instructionAddress, pageRelativeTarget, out var pageTarget))
            {
                mappedOperand = null!;
                diagnostic = $"AsmStone returned an ADRP page-relative target that cannot be normalized with checked source/displacement arithmetic at 0x{instructionAddress:X}.";
                return false;
            }

            target = pageTarget;
        }

        mappedOperand = new Aarch64SemanticOperand(
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
            operand.SemanticDomain)
        {
            RegisterModifierKind = registerModifierKind,
            RegisterModifierAmount = registerModifierAmount,
        };
        return true;
    }

    private static bool TryNormalizePageRelativeTarget(
        ulong instructionAddress,
        ulong decodedTarget,
        out ulong pageTarget)
    {
        pageTarget = default;
        long displacement;
        if (decodedTarget >= instructionAddress)
        {
            var positiveDisplacement = decodedTarget - instructionAddress;
            if (positiveDisplacement > 0xFFFFF000UL)
            {
                return false;
            }

            displacement = checked((long)positiveDisplacement);
        }
        else
        {
            var negativeMagnitude = instructionAddress - decodedTarget;
            if (negativeMagnitude > 0x1_0000_0000UL)
            {
                return false;
            }

            displacement = negativeMagnitude == 0x8000_0000_0000_0000UL
                ? long.MinValue
                : -checked((long)negativeMagnitude);
        }

        if ((displacement & 0xFFF) != 0)
        {
            return false;
        }

        var sourcePage = instructionAddress & ~0xFFFUL;
        if (displacement >= 0)
        {
            var distance = checked((ulong)displacement);
            if (sourcePage > ulong.MaxValue - distance)
            {
                return false;
            }

            pageTarget = sourcePage + distance;
        }
        else
        {
            var distance = displacement == long.MinValue
                ? 0x8000_0000_0000_0000UL
                : checked((ulong)-displacement);
            if (sourcePage < distance)
            {
                return false;
            }

            pageTarget = sourcePage - distance;
        }

        return (pageTarget & 0xFFFUL) == 0;
    }

    private static Aarch64OperandKind MapOperand(
        global::AsmStone.Model.A64Operand? operand,
        out Aarch64RegisterView? register,
        out IReadOnlyList<Aarch64RegisterView> registers,
        out Aarch64MemoryReference? memory,
        out long? immediate,
        out ulong? target,
        out string? registerModifierKind,
        out int registerModifierAmount)
    {
        register = null;
        registers = Array.Empty<Aarch64RegisterView>();
        memory = null;
        immediate = null;
        target = null;
        registerModifierKind = null;
        registerModifierAmount = 0;
        switch (operand)
        {
            case global::AsmStone.Model.RegisterOperand value:
                register = MapRegister(value.Register);
                if (value.Modifier is { } registerModifier)
                {
                    registerModifierKind = registerModifier.Kind.ToString();
                    registerModifierAmount = registerModifier.Amount;
                }

                return Aarch64OperandKind.Register;
            case global::AsmStone.Model.ModifiedRegisterOperand value:
                register = MapRegister(value.Register);
                if (value.TryGetModifier(out var modifier))
                {
                    registerModifierKind = modifier.Kind.ToString();
                    registerModifierAmount = modifier.Amount;
                }
                else
                {
                    registerModifierKind = "Unknown";
                }

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
                    value.WritesBack,
                    value.IndexModifierSemantics?.Kind.ToString(),
                    value.IndexModifierSemantics?.Amount ?? 0);
                return Aarch64OperandKind.Memory;
            case global::AsmStone.Model.SystemRegisterOperand value:
                immediate = value.Encoding;
                return Aarch64OperandKind.EncodedField;
            case global::AsmStone.Model.TargetOperand value:
                target = value.Address;
                return Aarch64OperandKind.Target;
            case global::AsmStone.Model.ImmediateOperand value:
                immediate = value.Value;
                return Aarch64OperandKind.Immediate;
            case global::AsmStone.Model.RegisterModifierOperand value:
                registerModifierKind = value.Modifier.Kind.ToString();
                registerModifierAmount = value.Modifier.Amount;
                return Aarch64OperandKind.EncodedField;
            case global::AsmStone.Model.EncodedFieldOperand value:
                if (!string.IsNullOrEmpty(value.Codec)
                    && global::AsmStone.Model.A64RegisterModifier.TryDecode(
                        value.Codec,
                        value.Value,
                        out var encodedModifier))
                {
                    registerModifierKind = encodedModifier.Kind.ToString();
                    registerModifierAmount = encodedModifier.Amount;
                }
                else if (IsRegisterModifierCodec(value.Codec))
                {
                    registerModifierKind = "Unknown";
                }

                return Aarch64OperandKind.EncodedField;
            case global::AsmStone.Model.FloatingImmediateOperand:
                return Aarch64OperandKind.Immediate;
            case null:
                return Aarch64OperandKind.Unknown;
            default:
                return Aarch64OperandKind.EncodedField;
        }
    }

    private static bool IsRegisterModifierCodec(string codec) =>
        codec is "logical_shifted_reg32" or "logical_shifted_reg64"
            or "arith_shifted_reg32" or "arith_shifted_reg64"
            or "arith_extendlsl64"
        || codec.StartsWith("arith_extended_reg", StringComparison.Ordinal);

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

        if (flags.HasFlag(A64InstructionFlags.IsCall))
        {
            return target.HasValue
                ? Aarch64ControlFlowKind.DirectCall
                : Aarch64ControlFlowKind.IndirectBranch;
        }

        if (!flags.HasFlag(A64InstructionFlags.IsBranch))
        {
            return Aarch64ControlFlowKind.None;
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
