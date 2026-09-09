using AsmStone.Generated;

namespace AsmStone.Model;

public enum A64OperandKind
{
    Register,
    VectorRegisterList,
    RegisterGroup,
    RegisterPair,
    SystemRegister,
    MatrixTileMask,
    MatrixRegister,
    ModifiedRegister,
    RegisterModifier,
    Immediate,
    FloatingImmediate,
    EncodedField,
    Target,
    Memory,
}

public readonly struct A64OperandView
{
    internal A64OperandView(
        string name,
        A64OperandKind kind,
        A64Register register,
        A64Register register1,
        A64Register register2,
        A64Register register3,
        int registerCount,
        int elementWidth,
        long immediate,
        double floatingImmediate,
        uint rawValue,
        ulong target,
        string codec,
        uint systemRegisterEncoding,
        byte matrixTileMask,
        A64Register baseRegister,
        long offset,
        A64Register indexRegister,
        bool hasIndex,
        A64MemoryAddressingMode memoryMode,
        uint indexModifier,
        bool hasIndexModifier,
        A64ImmediateSemanticKind immediateSemanticKind,
        A64EnumKind enumKind,
        A64PredicateMode predicateMode,
        A64MatrixRegisterKind matrixRegisterKind,
        int matrixRegisterIndex,
        int laneCount,
        int fractionalBits,
        int shiftAmount,
        int groupStride,
        A64RegisterModifierKind modifierKind,
        int modifierAmount,
        A64RegisterModifierKind indexModifierKind,
        int indexModifierAmount,
        int accessSize,
        A64MemoryOrdering ordering,
        A64OperandDirection direction,
        bool isImplicit,
        string? tiedTo,
        A64RegisterConstraint registerConstraint,
        int registerWidth,
        int fieldWidth,
        int scale,
        bool isSigned,
        bool allowsStackPointer,
        bool allowsZeroRegister,
        bool isPageRelative,
        string semanticDomain)
    {
        Name = name;
        Kind = kind;
        Register = register;
        Register1 = register1;
        Register2 = register2;
        Register3 = register3;
        RegisterCount = registerCount;
        ElementWidth = elementWidth;
        Immediate = immediate;
        FloatingImmediate = floatingImmediate;
        RawValue = rawValue;
        Target = target;
        Codec = codec;
        SystemRegisterEncoding = systemRegisterEncoding;
        MatrixTileMask = matrixTileMask;
        BaseRegister = baseRegister;
        Offset = offset;
        IndexRegister = indexRegister;
        HasIndex = hasIndex;
        MemoryMode = memoryMode;
        IndexModifier = indexModifier;
        HasIndexModifier = hasIndexModifier;
        ImmediateSemanticKind = immediateSemanticKind;
        EnumKind = enumKind;
        PredicateMode = predicateMode;
        MatrixRegisterKind = matrixRegisterKind;
        MatrixRegisterIndex = matrixRegisterIndex;
        LaneCount = laneCount;
        FractionalBits = fractionalBits;
        ShiftAmount = shiftAmount;
        GroupStride = groupStride;
        ModifierKind = modifierKind;
        ModifierAmount = modifierAmount;
        IndexModifierKind = indexModifierKind;
        IndexModifierAmount = indexModifierAmount;
        AccessSize = accessSize;
        Ordering = ordering;
        Direction = direction;
        IsImplicit = isImplicit;
        TiedTo = tiedTo;
        RegisterConstraint = registerConstraint;
        RegisterWidth = registerWidth;
        FieldWidth = fieldWidth;
        Scale = scale;
        IsSigned = isSigned;
        AllowsStackPointer = allowsStackPointer;
        AllowsZeroRegister = allowsZeroRegister;
        IsPageRelative = isPageRelative;
        SemanticDomain = semanticDomain;
    }

    public string Name { get; }

    public A64OperandKind Kind { get; }

    public A64Register Register { get; }

    public A64Register Register1 { get; }

    public A64Register Register2 { get; }

    public A64Register Register3 { get; }

    public int RegisterCount { get; }

    public int ElementWidth { get; }

    public long Immediate { get; }

    public double FloatingImmediate { get; }

    public uint RawValue { get; }

    public ulong Target { get; }

    public string Codec { get; }

    public uint SystemRegisterEncoding { get; }

    public byte MatrixTileMask { get; }

    public A64Register BaseRegister { get; }

    public long Offset { get; }

    public A64Register IndexRegister { get; }

    public bool HasIndex { get; }

    public A64MemoryAddressingMode MemoryMode { get; }

    public uint IndexModifier { get; }

    public bool HasIndexModifier { get; }

    public A64RegisterConstraint RegisterConstraint { get; }

    public int RegisterWidth { get; }

    public int FieldWidth { get; }

    public int Scale { get; }

    public bool IsSigned { get; }

    public bool AllowsStackPointer { get; }

    public bool AllowsZeroRegister { get; }

    public bool IsPageRelative { get; }

    public string SemanticDomain { get; }

    public A64ImmediateSemanticKind ImmediateSemanticKind { get; }

    public A64EnumKind EnumKind { get; }

    public A64PredicateMode PredicateMode { get; }

    public A64MatrixRegisterKind MatrixRegisterKind { get; }

    public int MatrixRegisterIndex { get; }

    public int LaneCount { get; }

    public int FractionalBits { get; }

    public int ShiftAmount { get; }

    public int GroupStride { get; }

    public A64RegisterModifierKind ModifierKind { get; }

    public int ModifierAmount { get; }

    public A64RegisterModifierKind IndexModifierKind { get; }

    public int IndexModifierAmount { get; }

    public int AccessSize { get; }

    public A64MemoryOrdering Ordering { get; }

    public A64OperandDirection Direction { get; }

    public bool IsImplicit { get; }

    public string? TiedTo { get; }

    internal A64OperandView WithBindingMetadataAndSemantics(
        A64RegisterConstraint registerConstraint,
        int registerWidth,
        int fieldWidth,
        int scale,
        bool isSigned,
        bool allowsStackPointer,
        bool allowsZeroRegister,
        bool isPageRelative,
        string semanticDomain,
        A64RegisterModifierKind fixedModifierKind,
        int fixedModifierAmount,
        int elementWidth,
        A64OperandDirection direction,
        bool isImplicit,
        string? tiedTo)
    {
        return new A64OperandView(
            this,
            registerConstraint,
            registerWidth,
            fieldWidth,
            scale,
            isSigned,
            allowsStackPointer,
            allowsZeroRegister,
            isPageRelative,
            semanticDomain,
            fixedModifierKind,
            fixedModifierAmount,
            elementWidth,
            direction,
            isImplicit,
            tiedTo);
    }

    private A64OperandView(
        A64OperandView source,
        A64RegisterConstraint registerConstraint,
        int registerWidth,
        int fieldWidth,
        int scale,
        bool isSigned,
        bool allowsStackPointer,
        bool allowsZeroRegister,
        bool isPageRelative,
        string semanticDomain,
        A64RegisterModifierKind fixedModifierKind,
        int fixedModifierAmount,
        int elementWidth,
        A64OperandDirection direction,
        bool isImplicit,
        string? tiedTo)
    {
        this = source;
        RegisterConstraint = registerConstraint;
        RegisterWidth = registerWidth;
        FieldWidth = fieldWidth;
        Scale = scale;
        IsSigned = isSigned;
        AllowsStackPointer = allowsStackPointer;
        AllowsZeroRegister = allowsZeroRegister;
        IsPageRelative = isPageRelative;
        SemanticDomain = semanticDomain;
        Direction = direction;
        IsImplicit = isImplicit;
        TiedTo = tiedTo;
        if (fixedModifierKind != A64RegisterModifierKind.Unknown)
        {
            ModifierKind = fixedModifierKind;
            ModifierAmount = fixedModifierAmount;
        }

        if (elementWidth != 0)
        {
            ElementWidth = elementWidth;
        }
    }

    internal static A64OperandView RegisterValue(string name, string codec, A64Register register)
    {
        return Create(name, A64OperandKind.Register, codec, register: register);
    }

    internal static A64OperandView RegisterValue(
        string name,
        string codec,
        A64Register register,
        int elementWidth,
        A64PredicateMode predicateMode)
    {
        return Create(
            name,
            A64OperandKind.Register,
            codec,
            register: register,
            elementWidth: elementWidth,
            predicateMode: predicateMode);
    }

    internal static A64OperandView ModifiedRegisterValue(
        string name,
        string codec,
        A64Register register,
        uint modifier)
    {
        A64RegisterModifier.TryDecode(codec, modifier, out var decodedModifier);
        return Create(
            name,
            A64OperandKind.ModifiedRegister,
            codec,
            register: register,
            rawValue: modifier,
            modifierKind: decodedModifier.Kind,
            modifierAmount: decodedModifier.Amount);
    }

    internal static A64OperandView RegisterModifierValue(
        string name,
        string codec,
        A64RegisterModifier modifier)
    {
        return Create(
            name,
            A64OperandKind.RegisterModifier,
            codec,
            rawValue: modifier.RawEncoding,
            modifierKind: modifier.Kind,
            modifierAmount: modifier.Amount);
    }

    internal static A64OperandView ImmediateValue(
        string name,
        string codec,
        long value,
        uint rawValue,
        A64ImmediateSemanticKind semanticKind = A64ImmediateSemanticKind.Plain,
        A64EnumKind enumKind = A64EnumKind.Unknown,
        int elementWidth = 0,
        int laneCount = 0,
        int fractionalBits = 0,
        int shiftAmount = 0)
    {
        return Create(
            name,
            A64OperandKind.Immediate,
            codec,
            immediate: value,
            rawValue: rawValue,
            immediateSemanticKind: semanticKind,
            enumKind: enumKind,
            elementWidth: elementWidth,
            laneCount: laneCount,
            fractionalBits: fractionalBits,
            shiftAmount: shiftAmount);
    }

    internal static A64OperandView FloatingImmediateValue(
        string name,
        string codec,
        double value,
        uint rawValue,
        A64ImmediateSemanticKind semanticKind = A64ImmediateSemanticKind.FloatingImmediate)
    {
        return Create(
            name,
            A64OperandKind.FloatingImmediate,
            codec,
            floatingImmediate: value,
            rawValue: rawValue,
            immediateSemanticKind: semanticKind);
    }

    internal static A64OperandView EncodedFieldValue(
        string name,
        string codec,
        uint value)
    {
        return Create(name, A64OperandKind.EncodedField, codec, rawValue: value);
    }

    internal static A64OperandView TargetValue(
        string name,
        string codec,
        ulong target,
        uint rawValue)
    {
        return Create(name, A64OperandKind.Target, codec, target: target, rawValue: rawValue);
    }

    internal static A64OperandView VectorListValue(
        string name,
        string codec,
        A64Register first,
        A64Register second,
        A64Register third,
        A64Register fourth,
        int count,
        int elementWidth)
    {
        return Create(
            name,
            A64OperandKind.VectorRegisterList,
            codec,
            register: first,
            register1: second,
            register2: third,
            register3: fourth,
            registerCount: count,
            elementWidth: elementWidth);
    }

    internal static A64OperandView RegisterGroupValue(
        string name,
        string codec,
        A64Register first,
        A64Register second,
        A64Register third,
        A64Register fourth,
        int count,
        int elementWidth,
        int stride = 1)
    {
        return Create(
            name,
            A64OperandKind.RegisterGroup,
            codec,
            register: first,
            register1: second,
            register2: third,
            register3: fourth,
            registerCount: count,
            elementWidth: elementWidth,
            groupStride: stride);
    }

    internal static A64OperandView RegisterPairValue(
        string name,
        string codec,
        A64Register first,
        A64Register second)
    {
        return Create(
            name,
            A64OperandKind.RegisterPair,
            codec,
            register: first,
            register1: second,
            registerCount: 2);
    }

    internal static A64OperandView MatrixRegisterValue(
        string name,
        string codec,
        A64MatrixRegisterKind kind,
        int index,
        int elementWidth,
        uint rawValue)
    {
        return Create(
            name,
            A64OperandKind.MatrixRegister,
            codec,
            elementWidth: elementWidth,
            rawValue: rawValue,
            matrixRegisterKind: kind,
            matrixRegisterIndex: index);
    }

    internal static A64OperandView SystemRegisterValue(string name, string codec, uint value)
    {
        return Create(
            name,
            A64OperandKind.SystemRegister,
            codec,
            rawValue: value,
            systemRegisterEncoding: value);
    }

    internal static A64OperandView MatrixTileMaskValue(string name, string codec, byte value)
    {
        return Create(
            name,
            A64OperandKind.MatrixTileMask,
            codec,
            rawValue: value,
            matrixTileMask: value);
    }

    internal static A64OperandView MemoryValue(
        string name,
        string codec,
        A64Register baseRegister,
        long offset,
        A64Register indexRegister,
        bool hasIndex,
        A64MemoryAddressingMode mode,
        uint indexModifier,
        bool hasIndexModifier,
        A64RegisterModifierKind indexModifierKind = A64RegisterModifierKind.Unknown,
        int indexModifierAmount = 0,
        int accessSize = 0,
        A64MemoryOrdering ordering = A64MemoryOrdering.None)
    {
        return Create(
            name,
            A64OperandKind.Memory,
            codec,
            baseRegister: baseRegister,
            offset: offset,
            indexRegister: indexRegister,
            hasIndex: hasIndex,
            memoryMode: mode,
            indexModifier: indexModifier,
            hasIndexModifier: hasIndexModifier,
            indexModifierKind: indexModifierKind,
            indexModifierAmount: indexModifierAmount,
            accessSize: accessSize,
            ordering: ordering);
    }

    private static A64OperandView Create(
        string name,
        A64OperandKind kind,
        string codec,
        A64Register register = default,
        A64Register register1 = default,
        A64Register register2 = default,
        A64Register register3 = default,
        int registerCount = 0,
        int elementWidth = 0,
        long immediate = 0,
        double floatingImmediate = 0,
        uint rawValue = 0,
        ulong target = 0,
        uint systemRegisterEncoding = 0,
        byte matrixTileMask = 0,
        A64Register baseRegister = default,
        long offset = 0,
        A64Register indexRegister = default,
        bool hasIndex = false,
        A64MemoryAddressingMode memoryMode = A64MemoryAddressingMode.Offset,
        uint indexModifier = 0,
        bool hasIndexModifier = false,
        A64ImmediateSemanticKind immediateSemanticKind = A64ImmediateSemanticKind.Plain,
        A64EnumKind enumKind = A64EnumKind.Unknown,
        A64PredicateMode predicateMode = A64PredicateMode.None,
        A64MatrixRegisterKind matrixRegisterKind = A64MatrixRegisterKind.Za,
        int matrixRegisterIndex = 0,
        int laneCount = 0,
        int fractionalBits = 0,
        int shiftAmount = 0,
        int groupStride = 1,
        A64RegisterModifierKind modifierKind = A64RegisterModifierKind.Unknown,
        int modifierAmount = 0,
        A64RegisterModifierKind indexModifierKind = A64RegisterModifierKind.Unknown,
        int indexModifierAmount = 0,
        int accessSize = 0,
        A64MemoryOrdering ordering = A64MemoryOrdering.None,
        A64OperandDirection direction = A64OperandDirection.Input,
        bool isImplicit = false,
        string? tiedTo = null,
        A64RegisterConstraint registerConstraint = default,
        int registerWidth = 0,
        int fieldWidth = 0,
        int scale = 1,
        bool isSigned = false,
        bool allowsStackPointer = false,
        bool allowsZeroRegister = false,
        bool isPageRelative = false,
        string semanticDomain = "")
    {
        return new A64OperandView(
            name,
            kind,
            register,
            register1,
            register2,
            register3,
            registerCount,
            elementWidth,
            immediate,
            floatingImmediate,
            rawValue,
            target,
            codec,
            systemRegisterEncoding,
            matrixTileMask,
            baseRegister,
            offset,
            indexRegister,
            hasIndex,
            memoryMode,
            indexModifier,
            hasIndexModifier,
            immediateSemanticKind,
            enumKind,
            predicateMode,
            matrixRegisterKind,
            matrixRegisterIndex,
            laneCount,
            fractionalBits,
            shiftAmount,
            groupStride,
            modifierKind,
            modifierAmount,
            indexModifierKind,
            indexModifierAmount,
            accessSize,
            ordering,
            direction,
            isImplicit,
            tiedTo,
            registerConstraint == default ? A64RegisterConstraint.Any : registerConstraint,
            registerWidth,
            fieldWidth,
            scale,
            isSigned,
            allowsStackPointer,
            allowsZeroRegister,
            isPageRelative,
            semanticDomain);
    }
}

public readonly ref struct A64InstructionView
{
    private readonly A64CompiledInstruction? plan;
    private readonly ReadOnlySpan<A64OperandView> operands;

    internal A64InstructionView(
        A64CompiledInstruction plan,
        uint encoding,
        ulong address,
        ReadOnlySpan<A64OperandView> operands)
    {
        this.plan = plan;
        Encoding = encoding;
        Address = address;
        this.operands = operands;
    }

    public uint Encoding { get; }

    public ulong Address { get; }

    public string SourceName => plan?.Info.Name ?? string.Empty;

    public string Mnemonic => plan?.Info.Mnemonic ?? string.Empty;

    public A64InstructionFlags Flags
    {
        get
        {
            if (plan is null)
            {
                return A64InstructionFlags.None;
            }

            var flags = plan.Info.Flags;
            var ordering = A64GeneratedMemory.Ordering(plan);
            if (ordering is A64MemoryOrdering.Acquire or A64MemoryOrdering.AcquireRelease)
            {
                flags |= A64InstructionFlags.IsAcquire;
            }

            if (ordering is A64MemoryOrdering.Release or A64MemoryOrdering.AcquireRelease)
            {
                flags |= A64InstructionFlags.IsRelease;
            }

            foreach (var binding in plan.Bindings)
            {
                if (binding.Codec?.OperandType == "OPERAND_PCREL")
                {
                    flags |= A64InstructionFlags.IsPcRelative;
                    break;
                }
            }

            return flags;
        }
    }

    public ReadOnlySpan<A64OperandView> Operands => operands;

    public int OperandCount => operands.Length;
}
