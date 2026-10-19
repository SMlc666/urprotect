using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Aarch64Semantics;

namespace UrProtect.Core.SemanticPlanning;

public static partial class SemanticPlanSnapshotCodec
{
    private sealed class SnapshotReader
    {
        private readonly BoundedReader reader;
        private int metadataBytes;
        private int externalProviderTables;
        private int externalProviderSymbols;
        private int externalProviderEntries;
        private int externalProviderStringBytes;
        private int externalProviderTableBytes;

        public SnapshotReader(ReadOnlyMemory<byte> source)
        {
            reader = new BoundedReader(source);
        }

        public bool IsAtEnd => Position == (ulong)reader.Length;

        public ulong Position { get; private set; }

        public DiagnosticCode FailureCode { get; private set; } = DiagnosticCode.SemanticPlanSnapshotMalformed;

        public string? FailureMessage { get; private set; }

        public ulong? FailureOffset { get; private set; }

        public bool TrySkip(ulong length)
        {
            if (!reader.Contains(Position, length))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated record.");
            }

            Position += length;
            return true;
        }

        public bool TryReadByte(out byte value)
        {
            value = default;
            if (!reader.TryReadByte(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated byte field.");
            }

            Position++;
            return true;
        }

        public bool TryReadUInt16(out ushort value)
        {
            value = default;
            if (!reader.TryReadUInt16(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated 16-bit field.");
            }

            Position += sizeof(ushort);
            return true;
        }

        public bool TryReadUInt32(out uint value)
        {
            value = default;
            if (!reader.TryReadUInt32(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated 32-bit field.");
            }

            Position += sizeof(uint);
            return true;
        }

        public bool TryReadUInt64(out ulong value)
        {
            value = default;
            if (!reader.TryReadUInt64(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated 64-bit field.");
            }

            Position += sizeof(ulong);
            return true;
        }

        public bool TryReadInt32(out int value)
        {
            value = default;
            if (!reader.TryReadInt32(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated signed 32-bit field.");
            }

            Position += sizeof(int);
            return true;
        }

        public bool TryReadInt64(out long value)
        {
            value = default;
            if (!reader.TryReadInt64(Position, out value))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a truncated signed 64-bit field.");
            }

            Position += sizeof(long);
            return true;
        }

        public bool TryReadCount(int maximum, out int count)
        {
            count = default;
            if (!TryReadUInt32(out var raw))
            {
                return false;
            }

            if (raw > (uint)maximum || raw > int.MaxValue)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot contains a collection count outside its bounded limit.");
            }

            count = (int)raw;
            return true;
        }

        public bool TryReadUtf8String(out string value) => TryReadUtf8StringCore(out value, externalProvider: false);

        public bool TryReadExternalProviderString(out string value) => TryReadUtf8StringCore(out value, externalProvider: true);

        private bool TryReadUtf8StringCore(out string value, bool externalProvider)
        {
            value = string.Empty;
            if (!TryReadUInt32(out var byteLength))
            {
                return false;
            }

            if (byteLength > SemanticPlanSnapshotLimits.MaximumStringBytes)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot contains oversized string metadata.");
            }

            if (!reader.TrySlice(Position, byteLength, out var bytes))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot string extends beyond its bounded input.");
            }

            try
            {
                value = StrictUtf8.GetString(bytes.Span);
            }
            catch (DecoderFallbackException)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains invalid UTF-8 metadata.");
            }

            if (metadataBytes > SemanticPlanSnapshotLimits.MaximumMetadataBytes - (int)byteLength)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot metadata exceeds its bounded byte limit.");
            }

            if (externalProvider
                && externalProviderStringBytes > SemanticPlanSnapshotLimits.MaximumExternalProviderStringBytes - (int)byteLength)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot exceeds its aggregate external-provider string limit.");
            }

            metadataBytes += (int)byteLength;
            if (externalProvider)
            {
                externalProviderStringBytes += (int)byteLength;
            }

            Position += byteLength;
            return true;
        }

        public bool TryAccountExternalProviderTableSymbols(int targetSymbolCount)
        {
            var symbolCount = (long)targetSymbolCount + 1;
            if (targetSymbolCount < 0
                || externalProviderTables >= SemanticPlanSnapshotLimits.MaximumExternalProviderTables
                || symbolCount > SemanticPlanSnapshotLimits.MaximumExternalProviderSymbols - externalProviderSymbols)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot exceeds an aggregate external-provider table or symbol limit.");
            }

            externalProviderTables++;
            externalProviderSymbols += (int)symbolCount;
            return true;
        }

        public bool TryAccountExternalProviderEntries(int entryCount)
        {
            if (entryCount < 0
                || entryCount > SemanticPlanSnapshotLimits.MaximumExternalProviderTableEntries - externalProviderEntries)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot exceeds its aggregate external-provider table-entry limit.");
            }

            externalProviderEntries += entryCount;
            return true;
        }

        public bool TryReadExternalProviderBytes(int maximum, out byte[] values)
        {
            values = Array.Empty<byte>();
            if (!TryReadUInt32(out var byteLength))
            {
                return false;
            }

            if (byteLength > maximum
                || byteLength > SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytes - externalProviderTableBytes)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    "The semantic-plan snapshot exceeds its bounded external-provider table-byte limit.");
            }

            if (!reader.TrySlice(Position, byteLength, out var bytes))
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The external-provider table bytes extend beyond the bounded snapshot input.");
            }

            values = bytes.ToArray();
            externalProviderTableBytes += checked((int)byteLength);
            Position += byteLength;
            return true;
        }

        public bool TryReadBool(out bool value)
        {
            value = false;
            if (!TryReadByte(out var raw))
            {
                return false;
            }

            if (raw > 1)
            {
                return Fail(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "The semantic-plan snapshot contains a non-canonical boolean value.");
            }

            value = raw != 0;
            return true;
        }

        public bool TryReadOptionalString(out string? value)
        {
            value = null;
            if (!TryReadBool(out var present))
            {
                return false;
            }

            if (!present)
            {
                return true;
            }

            if (!TryReadUtf8String(out var text))
            {
                return false;
            }

            value = text;
            return true;
        }

        public bool Fail(
            DiagnosticCode code,
            string message)
        {
            if (FailureMessage is null)
            {
                FailureCode = code;
                FailureMessage = message;
                FailureOffset = Position;
            }

            return false;
        }
    }

    private static bool TryReadAddressMapEntry(
        SnapshotReader reader,
        out AddressMapEntry? entry)
    {
        entry = null;
        if (!TryReadEntityId(reader, out var identity)
            || !TryReadOptionalEntityId(reader, out var outputIdentity)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadRange(reader, out var outputRange))
        {
            return false;
        }

        entry = new AddressMapEntry(identity, sourceRange, outputRange, outputIdentity);
        return true;
    }

    private static bool TryReadInstruction(
        SnapshotReader reader,
        out SemanticInstruction? instruction)
    {
        instruction = null;
        if (!reader.TryReadUInt64(out var sourceAddress)
            || !reader.TryReadUInt64(out var sourceFileOffset)
            || !reader.TryReadUtf8String(out var mnemonic)
            || !reader.TryReadUInt32(out var encoding)
            || !TryReadRange(reader, out var sourceRange)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumOperandsPerInstruction, out var operandCount))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(mnemonic))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains an empty instruction mnemonic.");
        }

        var operands = new List<SemanticOperand>(operandCount);
        for (var index = 0; index < operandCount; index++)
        {
            if (!TryReadOperand(reader, out var operand))
            {
                return false;
            }

            operands.Add(operand!);
        }

        if (!reader.TryReadCount(
                SemanticPlanSnapshotLimits.MaximumRegisterEffectsPerInstruction,
                out var registerEffectCount))
        {
            return false;
        }

        var registerEffects = new List<SemanticRegisterEffect>(registerEffectCount);
        for (var index = 0; index < registerEffectCount; index++)
        {
            if (!TryReadRegisterEffect(reader, out var effect))
            {
                return false;
            }

            registerEffects.Add(effect);
        }

        if (!reader.TryReadByte(out var flagEffects)
            || !reader.TryReadByte(out var controlFlow)
            || !TryReadOptionalTarget(reader, out var controlFlowTarget)
            || !TryReadOptionalExpression(reader, out var expression)
            || !TryReadOptionalLiteral(reader, out var literal)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumRelocationsPerInstruction, out var relocationCount))
        {
            return false;
        }

        var relocations = new List<RelocationBinding>(relocationCount);
        for (var index = 0; index < relocationCount; index++)
        {
            if (!TryReadRelocation(reader, out var relocation))
            {
                return false;
            }

            relocations.Add(relocation!);
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumReferencesPerInstruction, out var referenceCount))
        {
            return false;
        }

        var references = new List<SemanticReference>(referenceCount);
        for (var index = 0; index < referenceCount; index++)
        {
            if (!TryReadReference(reader, out var reference))
            {
                return false;
            }

            references.Add(reference!);
        }

        if (!reader.TryReadBool(out var opaquePreservation))
        {
            return false;
        }

        const SemanticFlagEffects knownFlags = SemanticFlagEffects.ReadNzcv | SemanticFlagEffects.WriteNzcv;
        if ((((SemanticFlagEffects)flagEffects & ~knownFlags) != SemanticFlagEffects.None)
            || !Enum.IsDefined(typeof(Aarch64ControlFlowKind), (Aarch64ControlFlowKind)controlFlow))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported instruction enum value.");
        }

        instruction = new SemanticInstruction(
            new VirtualAddress(sourceAddress),
            new FileOffset(sourceFileOffset),
            encoding,
            mnemonic,
            sourceRange,
            operands,
            registerEffects,
            (SemanticFlagEffects)flagEffects,
            (Aarch64ControlFlowKind)controlFlow,
            controlFlowTarget,
            expression,
            literal,
            relocations,
            references,
            opaquePreservation);
        return true;
    }

    private static bool TryReadOperand(
        SnapshotReader reader,
        out SemanticOperand? operand)
    {
        operand = null;
        if (!reader.TryReadUtf8String(out var name)
            || !reader.TryReadByte(out var kind)
            || !reader.TryReadByte(out var direction)
            || !reader.TryReadBool(out var isImplicit)
            || !reader.TryReadUtf8String(out var codec)
            || !reader.TryReadOptionalString(out var tiedTo)
            || !TryReadOptionalRegister(reader, out var register)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var registerCount))
        {
            return false;
        }

        var registers = new List<Aarch64RegisterView>(registerCount);
        for (var index = 0; index < registerCount; index++)
        {
            if (!TryReadRegister(reader, out var listRegister))
            {
                return false;
            }

            registers.Add(listRegister);
        }

        if (!TryReadOptionalMemory(reader, out var memory)
            || !TryReadOptionalInt64(reader, out var immediate)
            || !TryReadOptionalUInt64(reader, out var target)
            || !TryReadRegisterConstraint(reader, out var constraint)
            || !reader.TryReadInt32(out var registerWidth)
            || !reader.TryReadInt32(out var fieldWidth)
            || !reader.TryReadInt32(out var elementWidth)
            || !reader.TryReadBool(out var allowsStackPointer)
            || !reader.TryReadBool(out var allowsZeroRegister)
            || !reader.TryReadBool(out var isPageRelative)
            || !reader.TryReadUtf8String(out var semanticDomain))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(Aarch64OperandKind), (Aarch64OperandKind)kind)
            || !Enum.IsDefined(typeof(Aarch64OperandDirection), (Aarch64OperandDirection)direction))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported operand enum value.");
        }

        operand = new SemanticOperand(
            name,
            (Aarch64OperandKind)kind,
            (Aarch64OperandDirection)direction,
            isImplicit,
            codec,
            tiedTo,
            register,
            registers,
            memory,
            immediate,
            target,
            constraint,
            registerWidth,
            fieldWidth,
            elementWidth,
            allowsStackPointer,
            allowsZeroRegister,
            isPageRelative,
            semanticDomain);
        return true;
    }

    private static bool TryReadRegisterEffect(
        SnapshotReader reader,
        out SemanticRegisterEffect effect)
    {
        effect = default;
        if (!TryReadRegister(reader, out var register)
            || !reader.TryReadByte(out var kind)
            || !reader.TryReadBool(out var isImplicit))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticRegisterEffectKind), (SemanticRegisterEffectKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported register-effect enum value.");
        }

        effect = new SemanticRegisterEffect(register, (SemanticRegisterEffectKind)kind, isImplicit);
        return true;
    }

    private static bool TryReadRegister(
        SnapshotReader reader,
        out Aarch64RegisterView register)
    {
        register = default;
        if (!reader.TryReadByte(out var registerClass)
            || !reader.TryReadByte(out var index)
            || !reader.TryReadByte(out var width)
            || !reader.TryReadByte(out var role))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(Aarch64RegisterClass), (Aarch64RegisterClass)registerClass)
            || !Enum.IsDefined(typeof(Aarch64RegisterRole), (Aarch64RegisterRole)role))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported register enum value.");
        }

        register = new Aarch64RegisterView(
            (Aarch64RegisterClass)registerClass,
            index,
            width,
            (Aarch64RegisterRole)role);
        return true;
    }

    private static bool TryReadRegisterConstraint(
        SnapshotReader reader,
        out Aarch64RegisterConstraint constraint)
    {
        constraint = default;
        if (!reader.TryReadInt32(out var minimum)
            || !reader.TryReadInt32(out var maximum)
            || !reader.TryReadInt32(out var step)
            || !reader.TryReadUInt32(out var allowedMask))
        {
            return false;
        }

        constraint = new Aarch64RegisterConstraint(minimum, maximum, step, allowedMask);
        return true;
    }

    private static bool TryReadOptionalRegister(
        SnapshotReader reader,
        out Aarch64RegisterView? register)
    {
        register = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadRegister(reader, out var value))
        {
            return false;
        }

        register = value;
        return true;
    }

    private static bool TryReadOptionalMemory(
        SnapshotReader reader,
        out Aarch64MemoryReference? memory)
    {
        memory = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadRegister(reader, out var baseRegister)
            || !TryReadOptionalRegister(reader, out var index)
            || !reader.TryReadInt64(out var offset)
            || !reader.TryReadUtf8String(out var addressingMode)
            || !TryReadOptionalUInt32(reader, out var indexModifier)
            || !reader.TryReadInt32(out var accessSize)
            || !reader.TryReadUtf8String(out var ordering)
            || !reader.TryReadBool(out var writesBack)
            || !reader.TryReadOptionalString(out var indexModifierKind)
            || !reader.TryReadInt32(out var indexModifierAmount))
        {
            return false;
        }

        memory = new Aarch64MemoryReference(
            baseRegister,
            index,
            offset,
            addressingMode,
            indexModifier,
            accessSize,
            ordering,
            writesBack,
            indexModifierKind,
            indexModifierAmount);
        return true;
    }

    private static bool TryReadOptionalTarget(
        SnapshotReader reader,
        out SemanticTarget? target)
    {
        target = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadTarget(reader, out target))
        {
            return false;
        }

        return true;
    }

    private static bool TryReadTarget(
        SnapshotReader reader,
        out SemanticTarget? target)
    {
        target = null;
        if (!reader.TryReadByte(out var resolution)
            || !TryReadOptionalUInt64(reader, out var sourceAddress)
            || !TryReadOptionalEntityId(reader, out var identity)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var identityCount))
        {
            return false;
        }

        var identities = new List<SemanticEntityId>(identityCount);
        for (var index = 0; index < identityCount; index++)
        {
            if (!TryReadEntityId(reader, out var candidate))
            {
                return false;
            }

            identities.Add(candidate);
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var addressCount))
        {
            return false;
        }

        var addresses = new List<VirtualAddress>(addressCount);
        for (var index = 0; index < addressCount; index++)
        {
            if (!reader.TryReadUInt64(out var address))
            {
                return false;
            }

            addresses.Add(new VirtualAddress(address));
        }

        if (!reader.TryReadOptionalString(out var runtimeBinding)
            || !reader.TryReadOptionalString(out var diagnostic))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticTargetResolution), (SemanticTargetResolution)resolution))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported target resolution enum value.");
        }

        target = new SemanticTarget(
            (SemanticTargetResolution)resolution,
            sourceAddress is { } source ? new VirtualAddress(source) : null,
            identity,
            identities,
            addresses,
            runtimeBinding,
            diagnostic);
        return true;
    }

    private static bool TryReadOptionalExpression(
        SnapshotReader reader,
        out PcRelativeExpression? expression)
    {
        expression = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadByte(out var kind)
            || !reader.TryReadUInt64(out var place)
            || !TryReadTarget(reader, out var target)
            || !reader.TryReadInt32(out var scale)
            || !reader.TryReadBool(out var pageRelative)
            || !reader.TryReadInt64(out var addend))
        {
            return false;
        }

        if (target is null || !Enum.IsDefined(typeof(PcRelativeExpressionKind), (PcRelativeExpressionKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported PC-relative expression.");
        }

        expression = new PcRelativeExpression(
            (PcRelativeExpressionKind)kind,
            new VirtualAddress(place),
            target,
            scale,
            pageRelative,
            addend);
        return true;
    }

    private static bool TryReadOptionalLiteral(
        SnapshotReader reader,
        out LiteralReference? literal)
    {
        literal = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadTarget(reader, out var target)
            || !reader.TryReadInt32(out var accessSize)
            || !reader.TryReadBool(out var isLoad)
            || !TryReadOptionalRange(reader, out var poolRange))
        {
            return false;
        }

        if (target is null)
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot literal reference has no target.");
        }

        literal = new LiteralReference(target, accessSize, isLoad, poolRange);
        return true;
    }

    private static bool TryReadRelocation(
        SnapshotReader reader,
        out RelocationBinding? relocation)
    {
        relocation = null;
        if (!reader.TryReadByte(out var kind)
            || !TryReadTarget(reader, out var target)
            || !reader.TryReadInt64(out var addend)
            || !reader.TryReadUInt32(out var symbolIndex)
            || !reader.TryReadBool(out var isPlt)
            || !reader.TryReadOptionalString(out var symbolName)
            || !TryReadOptionalUInt32(reader, out var relocationType)
            || !TryReadOptionalUInt64(reader, out var rawInfo)
            || !TryReadOptionalUInt64(reader, out var relocationAddress)
            || !TryReadOptionalUInt64(reader, out var relocationTableAddress))
        {
            return false;
        }

        if (target is null || !Enum.IsDefined(typeof(Aarch64RelocationKind), (Aarch64RelocationKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported relocation binding.");
        }

        relocation = new RelocationBinding(
            (Aarch64RelocationKind)kind,
            target,
            addend,
            symbolIndex,
            isPlt,
            symbolName,
            relocationType,
            relocationAddress is { } address ? new VirtualAddress(address) : null,
            relocationTableAddress is { } tableAddress ? new VirtualAddress(tableAddress) : null)
        {
            RawInfo = rawInfo,
        };
        return true;
    }

    private static bool TryReadReference(
        SnapshotReader reader,
        out SemanticReference? reference)
    {
        reference = null;
        if (!reader.TryReadByte(out var kind)
            || !TryReadTarget(reader, out var target)
            || !reader.TryReadInt32(out var operandIndex)
            || !TryReadOptionalExpression(reader, out var expression)
            || !TryReadOptionalLiteral(reader, out var literal)
            || !TryReadOptionalRelocation(reader, out var relocation)
            || !reader.TryReadOptionalString(out var description))
        {
            return false;
        }

        if (target is null || !Enum.IsDefined(typeof(SemanticReferenceKind), (SemanticReferenceKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported semantic reference.");
        }

        reference = new SemanticReference(
            (SemanticReferenceKind)kind,
            target,
            operandIndex,
            expression,
            literal,
            relocation,
            description);
        return true;
    }

    private static bool TryReadOptionalRelocation(
        SnapshotReader reader,
        out RelocationBinding? relocation)
    {
        relocation = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        return TryReadRelocation(reader, out relocation);
    }

    private static bool TryReadFixup(
        SnapshotReader reader,
        out SemanticFixup? fixup,
        out SemanticFixupResolutionState state)
    {
        fixup = null;
        state = default;
        if (!reader.TryReadByte(out var stateValue)
            || !reader.TryReadByte(out var kind)
            || !reader.TryReadUInt64(out var sourceAddress)
            || !reader.TryReadUInt64(out var sourceFileOffset)
            || !reader.TryReadUInt32(out var originalEncoding)
            || !TryReadTarget(reader, out var target)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadOptionalExpression(reader, out var expression)
            || !TryReadOptionalRelocation(reader, out var relocation)
            || !reader.TryReadByte(out var relaxation)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumRelaxationOptions, out var optionCount))
        {
            return false;
        }

        var options = new List<SemanticRelaxationKind>(optionCount);
        for (var index = 0; index < optionCount; index++)
        {
            if (!reader.TryReadByte(out var option))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(SemanticRelaxationKind), (SemanticRelaxationKind)option))
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The semantic-plan snapshot contains an unsupported relaxation option.");
            }

            options.Add((SemanticRelaxationKind)option);
        }

        if (target is null
            || !Enum.IsDefined(typeof(SemanticFixupResolutionState), (SemanticFixupResolutionState)stateValue)
            || !Enum.IsDefined(typeof(SemanticFixupKind), (SemanticFixupKind)kind)
            || !Enum.IsDefined(typeof(SemanticRelaxationKind), (SemanticRelaxationKind)relaxation))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported fixup enum value.");
        }

        state = (SemanticFixupResolutionState)stateValue;
        fixup = new SemanticFixup(
            (SemanticFixupKind)kind,
            new VirtualAddress(sourceAddress),
            new FileOffset(sourceFileOffset),
            originalEncoding,
            target,
            sourceRange,
            expression,
            relocation,
            (SemanticRelaxationKind)relaxation,
            options);
        return true;
    }

    private static bool TryReadExtension(
        SnapshotReader reader,
        out ISemanticPlanExtension? extension)
    {
        extension = null;
        if (!reader.TryReadByte(out var kind)
            || !Enum.IsDefined(typeof(SemanticPlanExtensionKind), (SemanticPlanExtensionKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported extension kind.");
        }

        switch ((SemanticPlanExtensionKind)kind)
        {
            case SemanticPlanExtensionKind.IndirectTargets:
                if (!TryReadEntityId(reader, out var indirectSource)
                    || !reader.TryReadUInt64(out var indirectAddress)
                    || !TryReadTarget(reader, out var indirectTarget)
                    || !reader.TryReadUtf8String(out var indirectDiagnostic))
                {
                    return false;
                }

                if (indirectTarget is null || string.IsNullOrWhiteSpace(indirectDiagnostic))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The indirect-target extension has no target or diagnostic.");
                }

                extension = new SemanticIndirectTargetExtension(
                    indirectSource,
                    new VirtualAddress(indirectAddress),
                    indirectTarget,
                    indirectDiagnostic);
                return true;
            case SemanticPlanExtensionKind.UnresolvedReference:
                if (!TryReadEntityId(reader, out var unresolvedSource)
                    || !reader.TryReadUInt64(out var unresolvedAddress)
                    || !reader.TryReadByte(out var referenceKind)
                    || !TryReadTarget(reader, out var unresolvedTarget)
                    || !reader.TryReadUtf8String(out var unresolvedDiagnostic))
                {
                    return false;
                }

                if (unresolvedTarget is null
                    || string.IsNullOrWhiteSpace(unresolvedDiagnostic)
                    || !Enum.IsDefined(typeof(SemanticReferenceKind), (SemanticReferenceKind)referenceKind))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotUnsupported,
                        "The unresolved-reference extension has an invalid target or reference kind.");
                }

                extension = new SemanticUnresolvedReferenceExtension(
                    unresolvedSource,
                    new VirtualAddress(unresolvedAddress),
                    (SemanticReferenceKind)referenceKind,
                    unresolvedTarget,
                    unresolvedDiagnostic);
                return true;
            case SemanticPlanExtensionKind.RelocationBinding:
                if (!TryReadEntityId(reader, out var relocationSite)
                    || !TryReadRelocation(reader, out var relocationBinding)
                    || !reader.TryReadUtf8String(out var relocationDiagnostic))
                {
                    return false;
                }

                if (relocationBinding is null || string.IsNullOrWhiteSpace(relocationDiagnostic))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The relocation extension has no binding or diagnostic.");
                }

                extension = new SemanticRelocationBindingExtension(
                    relocationSite,
                    relocationBinding,
                    relocationDiagnostic);
                return true;
            case SemanticPlanExtensionKind.TlsBinding:
                if (!TryReadTlsBinding(reader, out var tlsBinding)
                    || !reader.TryReadOptionalString(out var tlsDiagnostic))
                {
                    return false;
                }

                extension = new SemanticTlsBindingExtension(tlsBinding!, tlsDiagnostic);
                return true;
            case SemanticPlanExtensionKind.DynamicImportCall:
                if (!TryReadEntityId(reader, out var callIdentity)
                    || !reader.TryReadUInt64(out var callAddress)
                    || !TryReadRegister(reader, out var targetRegister)
                    || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumProducerAddresses, out var producerCount))
                {
                    return false;
                }

                var producerAddresses = new List<VirtualAddress>(producerCount);
                for (var index = 0; index < producerCount; index++)
                {
                    if (!reader.TryReadUInt64(out var producerAddress))
                    {
                        return false;
                    }

                    producerAddresses.Add(new VirtualAddress(producerAddress));
                }

                if (!reader.TryReadUInt64(out var pageProducerAddress)
                    || !reader.TryReadUInt64(out var loadProducerAddress)
                    || !reader.TryReadUInt64(out var pageAddress)
                    || !TryReadRange(reader, out var gotRange)
                    || !TryReadEntityId(reader, out var relocationSiteIdentity)
                    || !reader.TryReadUInt64(out var relocationOffset)
                    || !reader.TryReadUInt64(out var relocationInfo)
                    || !reader.TryReadInt64(out var relocationAddend)
                    || !reader.TryReadBool(out var relocationIsPlt)
                    || !reader.TryReadUInt64(out var relocationTableAddress)
                    || !reader.TryReadUInt32(out var symbolIndex)
                    || !reader.TryReadUInt32(out var symbolNameOffset)
                    || !reader.TryReadUtf8String(out var symbolName)
                    || !reader.TryReadByte(out var symbolInfo)
                    || !reader.TryReadByte(out var symbolOther)
                    || !reader.TryReadByte(out var symbolBinding)
                    || !reader.TryReadByte(out var symbolType)
                    || !reader.TryReadByte(out var symbolVisibility)
                    || !reader.TryReadUInt16(out var symbolSectionIndex)
                    || !reader.TryReadUInt64(out var symbolValue)
                    || !reader.TryReadUInt64(out var symbolSize)
                    || !reader.TryReadBool(out var hasVersionIndex))
                {
                    return false;
                }

                ushort? symbolVersionIndexRaw = null;
                if (hasVersionIndex)
                {
                    if (!reader.TryReadUInt16(out var versionIndexRaw))
                    {
                        return false;
                    }

                    symbolVersionIndexRaw = versionIndexRaw;
                }

                if (!reader.TryReadBool(out var hasVersionRequirement))
                {
                    return false;
                }

                SemanticDynamicImportVersionRequirement? versionRequirement = null;
                if (hasVersionRequirement)
                {
                    if (!reader.TryReadUInt16(out var recordVersion)
                        || !reader.TryReadUInt16(out var auxiliaryCount)
                        || !reader.TryReadUInt32(out var fileNameOffset)
                        || !reader.TryReadUInt32(out var auxiliaryOffset)
                        || !reader.TryReadUInt32(out var nextOffset)
                        || !reader.TryReadUtf8String(out var fileName)
                        || !reader.TryReadUInt32(out var versionHash)
                        || !reader.TryReadUInt16(out var versionFlags)
                        || !reader.TryReadUInt16(out var auxiliaryOther)
                        || !reader.TryReadUInt32(out var nameOffset)
                        || !reader.TryReadUtf8String(out var versionName))
                    {
                        return false;
                    }

                    versionRequirement = new SemanticDynamicImportVersionRequirement(
                        recordVersion,
                        auxiliaryCount,
                        fileNameOffset,
                        auxiliaryOffset,
                        nextOffset,
                        fileName,
                        versionHash,
                        versionFlags,
                        auxiliaryOther,
                        nameOffset,
                        versionName);
                }

                if (string.IsNullOrWhiteSpace(symbolName))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The dynamic-import call extension has no dynamic-symbol name.");
                }

                extension = new SemanticDynamicImportCallExtension(
                    callIdentity,
                    new VirtualAddress(callAddress),
                    targetRegister,
                    producerAddresses,
                    new VirtualAddress(pageProducerAddress),
                    new VirtualAddress(loadProducerAddress),
                    new VirtualAddress(pageAddress),
                    gotRange,
                    relocationSiteIdentity,
                    relocationOffset,
                    relocationInfo,
                    relocationAddend,
                    relocationIsPlt,
                    new VirtualAddress(relocationTableAddress),
                    symbolIndex,
                    symbolNameOffset,
                    symbolName,
                    symbolInfo,
                    symbolOther,
                    symbolBinding,
                    symbolType,
                    symbolVisibility,
                    symbolSectionIndex,
                    symbolValue,
                    symbolSize,
                    symbolVersionIndexRaw,
                    versionRequirement);
                return true;
            case SemanticPlanExtensionKind.JumpTable:
                if (!TryReadEntityId(reader, out var tableIdentity)
                    || !TryReadRange(reader, out var tableRange)
                    || !reader.TryReadInt32(out var entrySize)
                    || !reader.TryReadOptionalString(out var tableEncoding)
                    || !reader.TryReadBool(out var hasBaseAddress))
                {
                    return false;
                }

                ulong? baseAddress = null;
                if (hasBaseAddress)
                {
                    if (!reader.TryReadUInt64(out var rawBaseAddress))
                    {
                        return false;
                    }

                    baseAddress = rawBaseAddress;
                }

                if (!reader.TryReadBool(out var hasTargetBaseAddress))
                {
                    return false;
                }

                ulong? targetBaseAddress = null;
                if (hasTargetBaseAddress)
                {
                    if (!reader.TryReadUInt64(out var rawTargetBaseAddress))
                    {
                        return false;
                    }

                    targetBaseAddress = rawTargetBaseAddress;
                }

                if (!TryReadOptionalEntityId(reader, out var sourceInstruction)
                    || !reader.TryReadBool(out var isSigned)
                    || !reader.TryReadInt32(out var scale)
                    || !reader.TryReadInt64(out var addend)
                    || !reader.TryReadInt32(out var lowerBound)
                    || !reader.TryReadInt32(out var upperBound)
                    || !TryReadOptionalTarget(reader, out var defaultTarget)
                    || !reader.TryReadByte(out var ownership)
                    || !reader.TryReadByte(out var rewritePolicy)
                    || !TryReadOptionalRange(reader, out var outputRange)
                    || !reader.TryReadOptionalString(out var tableDiagnostic)
                    || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTargetsPerJumpTable, out var targetCount))
                {
                    return false;
                }

                var targets = new List<SemanticTarget>(targetCount);
                for (var index = 0; index < targetCount; index++)
                {
                    if (!TryReadTarget(reader, out var target) || target is null)
                    {
                        return reader.Fail(
                            DiagnosticCode.SemanticPlanSnapshotMalformed,
                            "The jump-table extension contains a null target.");
                    }

                    targets.Add(target);
                }

                if (entrySize <= 0
                    || !Enum.IsDefined(typeof(SemanticJumpTableOwnership), (SemanticJumpTableOwnership)ownership)
                    || !Enum.IsDefined(typeof(SemanticJumpTableRewritePolicy), (SemanticJumpTableRewritePolicy)rewritePolicy))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The jump-table extension has an invalid structured contract.");
                }

                if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTargetsPerJumpTable, out var entryCount))
                {
                    return false;
                }

                var entries = new List<SemanticJumpTableEntryBinding>(entryCount);
                for (var index = 0; index < entryCount; index++)
                {
                    if (!TryReadEntityId(reader, out var entryIdentity)
                        || !reader.TryReadInt32(out var entryIndex)
                        || !reader.TryReadInt32(out var encodedValue)
                        || !TryReadRange(reader, out var entryRange)
                        || !TryReadTarget(reader, out var entryTarget)
                        || entryTarget is null)
                    {
                        return false;
                    }

                    entries.Add(new SemanticJumpTableEntryBinding(
                        entryIdentity,
                        entryIndex,
                        encodedValue,
                        entryRange,
                        entryTarget));
                }

                if (!reader.TryReadBool(out var ownerInventoryComplete)
                    || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumJumpTableReferenceProducers, out var referenceProducerCount))
                {
                    return false;
                }

                var referenceProducers = new List<Aarch64JumpTableReferenceProducer>(referenceProducerCount);
                for (var index = 0; index < referenceProducerCount; index++)
                {
                    if (!reader.TryReadUInt64(out var instructionAddress)
                        || !reader.TryReadByte(out var producerKindValue)
                        || !Enum.IsDefined(typeof(Aarch64JumpTableReferenceKind), (Aarch64JumpTableReferenceKind)producerKindValue))
                    {
                        return reader.Fail(
                            DiagnosticCode.SemanticPlanSnapshotMalformed,
                            "The jump-table reference-producer evidence is malformed.");
                    }

                    referenceProducers.Add(new Aarch64JumpTableReferenceProducer(
                        instructionAddress,
                        (Aarch64JumpTableReferenceKind)producerKindValue));
                }

                if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumJumpTableOwnerReferences, out var ownerReferenceCount))
                {
                    return false;
                }

                var ownerReferences = new List<Aarch64JumpTableOwnerReference>(ownerReferenceCount);
                for (var index = 0; index < ownerReferenceCount; index++)
                {
                    if (!reader.TryReadUInt64(out var ownerInstructionAddress)
                        || !reader.TryReadInt32(out var relocationSectionIndex)
                        || !reader.TryReadUInt32(out var symbolTableSectionIndex)
                        || !reader.TryReadUInt32(out var targetSectionIndex)
                        || !reader.TryReadUInt32(out var ownerFunctionSectionIndex)
                        || !reader.TryReadUInt32(out var ownerSectionName)
                        || !reader.TryReadUInt32(out var ownerSectionType)
                        || !reader.TryReadUInt64(out var ownerSectionFlags)
                        || !reader.TryReadUInt64(out var ownerSectionAddress)
                        || !reader.TryReadUInt64(out var ownerSectionOffset)
                        || !reader.TryReadUInt64(out var ownerSectionSize)
                        || !reader.TryReadUInt32(out var ownerSectionLink)
                        || !reader.TryReadUInt32(out var ownerSectionInfo)
                        || !reader.TryReadUInt64(out var ownerSectionAlignment)
                        || !reader.TryReadUInt64(out var ownerSectionEntrySize)
                        || !reader.TryReadUInt64(out var relocationSourceAddress)
                        || !reader.TryReadUInt32(out var relocationType)
                        || !reader.TryReadInt64(out var ownerRelocationAddend)
                        || !reader.TryReadUInt32(out var ownerSymbolIndex)
                        || !reader.TryReadUtf8String(out var ownerSymbolName)
                        || !reader.TryReadByte(out var ownerSymbolBinding)
                        || !reader.TryReadByte(out var ownerSymbolType)
                        || !reader.TryReadByte(out var ownerSymbolVisibility)
                        || !reader.TryReadUInt16(out var ownerSymbolSectionIndex)
                        || !reader.TryReadUInt64(out var ownerSymbolValue)
                        || !reader.TryReadUInt64(out var ownerSymbolSize)
                        || !reader.TryReadUtf8String(out var ownerFunctionName)
                        || !reader.TryReadUInt64(out var ownerFunctionStart)
                        || !reader.TryReadUInt64(out var ownerFunctionSize)
                        || !reader.TryReadBool(out var isSelectedFunction))
                    {
                        return false;
                    }

                    ownerReferences.Add(new Aarch64JumpTableOwnerReference(
                        ownerInstructionAddress,
                        relocationSectionIndex,
                        symbolTableSectionIndex,
                        targetSectionIndex,
                        ownerFunctionSectionIndex,
                        new SectionHeader(
                            ownerSectionName,
                            ownerSectionType,
                            ownerSectionFlags,
                            ownerSectionAddress,
                            ownerSectionOffset,
                            ownerSectionSize,
                            ownerSectionLink,
                            ownerSectionInfo,
                            ownerSectionAlignment,
                            ownerSectionEntrySize),
                        relocationSourceAddress,
                        relocationType,
                        ownerRelocationAddend,
                        ownerSymbolIndex,
                        ownerSymbolName,
                        ownerSymbolBinding,
                        ownerSymbolType,
                        ownerSymbolVisibility,
                        ownerSymbolSectionIndex,
                        ownerSymbolValue,
                        ownerSymbolSize,
                        ownerFunctionName,
                        ownerFunctionStart,
                        ownerFunctionSize,
                        isSelectedFunction));
                }

                extension = new SemanticJumpTableExtension(
                    tableIdentity,
                    tableRange,
                    entrySize,
                    targets,
                    tableEncoding,
                    baseAddress is { } rawBase ? new VirtualAddress(rawBase) : null,
                    targetBaseAddress is { } rawTargetBase ? new VirtualAddress(rawTargetBase) : null,
                    sourceInstruction,
                    isSigned,
                    scale,
                    addend,
                    lowerBound,
                    upperBound,
                    defaultTarget,
                    (SemanticJumpTableOwnership)ownership,
                    (SemanticJumpTableRewritePolicy)rewritePolicy,
                    outputRange,
                    entries,
                    tableDiagnostic,
                    referenceProducers,
                    ownerReferences,
                    ownerInventoryComplete);
                return true;
            case SemanticPlanExtensionKind.StaticFunctionPointerCall:
                return TryReadStaticFunctionPointerCallExtension(reader, out extension);
            case SemanticPlanExtensionKind.ExternalJumpTable:
                return TryReadExternalJumpTableExtension(reader, out extension);
            case SemanticPlanExtensionKind.CfiEffect:
                if (!TryReadEntityId(reader, out var cfiIdentity)
                    || !TryReadRange(reader, out var cfiRange)
                    || !reader.TryReadUtf8String(out var cfiEffect)
                    || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCfiRegisterEffects, out var effectCount))
                {
                    return false;
                }

                var effects = new List<SemanticRegisterEffect>(effectCount);
                for (var index = 0; index < effectCount; index++)
                {
                    if (!TryReadRegisterEffect(reader, out var effect))
                    {
                        return false;
                    }

                    effects.Add(effect);
                }

                if (!reader.TryReadOptionalString(out var cfiDiagnostic))
                {
                    return false;
                }

                if (string.IsNullOrWhiteSpace(cfiEffect))
                {
                    return reader.Fail(
                        DiagnosticCode.SemanticPlanSnapshotMalformed,
                        "The CFI extension has no effect description.");
                }

                extension = new SemanticCfiEffectExtension(
                    cfiIdentity,
                    cfiRange,
                    cfiEffect,
                    effects,
                    cfiDiagnostic);
                return true;
            default:
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The semantic-plan snapshot extension kind is not supported.");
        }
    }

    private static bool TryReadExternalJumpTableExtension(
        SnapshotReader reader,
        out ISemanticPlanExtension? extension)
    {
        extension = null;
        if (!reader.TryReadExternalProviderString(out var identityValue)
            || !reader.TryReadExternalProviderString(out var providerSoname)
            || !reader.TryReadExternalProviderString(out var providerBuildId)
            || !reader.TryReadExternalProviderString(out var providerSha256)
            || !reader.TryReadUInt64(out var providerFileSize)
            || !reader.TryReadByte(out var encoding)
            || !TryReadExternalProviderSymbol(reader, out var tableObject))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticExternalJumpTableEncoding), (SemanticExternalJumpTableEncoding)encoding))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The external-provider table encoding is unsupported.");
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumExternalProviderSymbolsPerTable, out var targetSymbolCount)
            || !reader.TryAccountExternalProviderTableSymbols(targetSymbolCount))
        {
            return false;
        }

        var targetSymbols = new List<SemanticExternalProviderSymbol>(targetSymbolCount);
        for (var index = 0; index < targetSymbolCount; index++)
        {
            if (!TryReadExternalProviderSymbol(reader, out var targetSymbol))
            {
                return false;
            }

            targetSymbols.Add(targetSymbol!);
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumExternalProviderTableEntriesPerTable, out var entryCount)
            || !reader.TryAccountExternalProviderEntries(entryCount))
        {
            return false;
        }

        var entries = new List<SemanticExternalJumpTableEntryFact>(entryCount);
        for (var index = 0; index < entryCount; index++)
        {
            if (!reader.TryReadInt32(out var entryIndex)
                || !reader.TryReadInt32(out var displacement)
                || !reader.TryReadByte(out var targetSymbolTable)
                || !reader.TryReadUInt32(out var targetSymbolIndex))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(ElfSymbolTableKind), (ElfSymbolTableKind)targetSymbolTable))
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "An external-provider table entry contains an unsupported target symbol-table kind.");
            }

            entries.Add(new SemanticExternalJumpTableEntryFact(
                entryIndex,
                displacement,
                (ElfSymbolTableKind)targetSymbolTable,
                targetSymbolIndex));
        }

        if (!reader.TryReadExternalProviderBytes(
                SemanticPlanSnapshotLimits.MaximumExternalProviderTableBytesPerTable,
                out var tableBytes))
        {
            return false;
        }

        extension = new SemanticExternalJumpTableExtension(
            new SemanticExternalProviderTableIdentity(identityValue),
            providerSoname,
            providerBuildId,
            providerSha256,
            providerFileSize,
            tableObject!,
            targetSymbols,
            entries,
            tableBytes,
            (SemanticExternalJumpTableEncoding)encoding);
        return true;
    }

    private static bool TryReadExternalProviderSymbol(
        SnapshotReader reader,
        out SemanticExternalProviderSymbol? symbol)
    {
        symbol = null;
        if (!reader.TryReadExternalProviderString(out var name)
            || !reader.TryReadByte(out var symbolTable)
            || !reader.TryReadUInt32(out var symbolIndex)
            || !reader.TryReadByte(out var binding)
            || !reader.TryReadByte(out var type)
            || !reader.TryReadByte(out var visibility)
            || !reader.TryReadUInt16(out var sectionIndex)
            || !reader.TryReadUInt64(out var fileOffset)
            || !reader.TryReadUInt64(out var virtualAddress)
            || !reader.TryReadUInt64(out var size)
            || !reader.TryReadUInt32(out var loadSegmentFlags))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(ElfSymbolTableKind), (ElfSymbolTableKind)symbolTable))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "An external-provider symbol contains an unsupported symbol-table kind.");
        }

        symbol = new SemanticExternalProviderSymbol(
            name,
            (ElfSymbolTableKind)symbolTable,
            symbolIndex,
            binding,
            type,
            visibility,
            sectionIndex,
            new SemanticExternalProviderRange(
                new SemanticExternalProviderFileOffset(fileOffset),
                new SemanticExternalProviderAddress(virtualAddress),
                size),
            loadSegmentFlags);
        return true;
    }

    private static bool TryReadStaticFunctionPointerCallExtension(
        SnapshotReader reader,
        out ISemanticPlanExtension? extension)
    {
        extension = null;
        if (!TryReadEntityId(reader, out var sourceIdentity)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadRegister(reader, out var targetRegister)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumProducerAddresses, out var producerCount))
        {
            return false;
        }

        var producers = new List<VirtualAddress>(producerCount);
        for (var index = 0; index < producerCount; index++)
        {
            if (!reader.TryReadUInt64(out var producerAddress))
            {
                return false;
            }

            producers.Add(new VirtualAddress(producerAddress));
        }

        if (!reader.TryReadInt64(out var stackSlotOffset)
            || !reader.TryReadUtf8String(out var ownerName)
            || !reader.TryReadByte(out var ownerTable)
            || !reader.TryReadUInt32(out var ownerTableIndex)
            || !reader.TryReadByte(out var ownerBinding)
            || !reader.TryReadByte(out var ownerOther)
            || !reader.TryReadUInt16(out var ownerSectionIndex)
            || !reader.TryReadUInt64(out var ownerValue)
            || !reader.TryReadUInt64(out var ownerSize)
            || !reader.TryReadInt32(out var relocationSectionIndex)
            || !TryReadSectionHeader(reader, out var relocationSectionHeader)
            || !reader.TryReadUInt32(out var symbolTableSectionIndex)
            || !TryReadSectionHeader(reader, out var symbolTableSectionHeader)
            || !TryReadSectionHeader(reader, out var callerSectionHeader)
            || !TryReadSectionHeader(reader, out var targetSectionHeader)
            || !TryReadStaticFunctionPointerRelocationRow(reader, out var adrpRelocation)
            || !TryReadStaticFunctionPointerRelocationRow(reader, out var addRelocation)
            || !TryReadRange(reader, out var targetSourceRange)
            || !TryReadEntityId(reader, out var targetMappingIdentity)
            || !TryReadRange(reader, out var targetOutputRange)
            || !reader.TryReadByte(out var mappingPolicy))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(ElfSymbolTableKind), (ElfSymbolTableKind)ownerTable)
            || !Enum.IsDefined(typeof(SemanticStaticFunctionPointerMappingPolicy), (SemanticStaticFunctionPointerMappingPolicy)mappingPolicy))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The static function-pointer owner contains an unsupported symbol-table or mapping policy enum.");
        }

        extension = new SemanticStaticFunctionPointerCallExtension(
            sourceIdentity,
            sourceRange,
            targetRegister,
            producers,
            stackSlotOffset,
            new ElfFunctionSymbol(
                ownerName,
                (ElfSymbolTableKind)ownerTable,
                ownerTableIndex,
                ownerBinding,
                ownerOther,
                ownerSectionIndex,
                ownerValue,
                ownerSize),
            relocationSectionIndex,
            relocationSectionHeader,
            symbolTableSectionIndex,
            symbolTableSectionHeader,
            callerSectionHeader,
            targetSectionHeader,
            adrpRelocation,
            addRelocation,
            targetSourceRange,
            targetMappingIdentity,
            targetOutputRange,
            (SemanticStaticFunctionPointerMappingPolicy)mappingPolicy);
        return true;
    }

    private static bool TryReadSectionHeader(SnapshotReader reader, out SectionHeader section)
    {
        section = default;
        if (!reader.TryReadUInt32(out var name)
            || !reader.TryReadUInt32(out var type)
            || !reader.TryReadUInt64(out var flags)
            || !reader.TryReadUInt64(out var address)
            || !reader.TryReadUInt64(out var offset)
            || !reader.TryReadUInt64(out var size)
            || !reader.TryReadUInt32(out var link)
            || !reader.TryReadUInt32(out var info)
            || !reader.TryReadUInt64(out var alignment)
            || !reader.TryReadUInt64(out var entrySize))
        {
            return false;
        }

        section = new SectionHeader(name, type, flags, address, offset, size, link, info, alignment, entrySize);
        return true;
    }

    private static bool TryReadStaticFunctionPointerRelocationRow(
        SnapshotReader reader,
        out SemanticStaticFunctionPointerRelocationRow row)
    {
        row = null!;
        if (!reader.TryReadInt32(out var relocationSectionIndex)
            || !reader.TryReadUInt64(out var relocationSectionFileOffset)
            || !reader.TryReadUInt64(out var relocationSectionAddress)
            || !reader.TryReadUInt32(out var symbolTableSectionIndex)
            || !reader.TryReadUInt32(out var targetSectionIndex)
            || !reader.TryReadUInt64(out var relocationSourceAddress)
            || !reader.TryReadUInt64(out var siteAddress)
            || !reader.TryReadUInt64(out var info)
            || !reader.TryReadUInt32(out var type)
            || !reader.TryReadUInt32(out var symbolIndex)
            || !reader.TryReadInt64(out var addend)
            || !reader.TryReadBool(out var isPlt)
            || !reader.TryReadUInt32(out var symbolNameOffset)
            || !reader.TryReadUtf8String(out var name)
            || !reader.TryReadByte(out var symbolInfo)
            || !reader.TryReadByte(out var symbolOther)
            || !reader.TryReadUInt16(out var symbolSectionIndex)
            || !reader.TryReadUInt64(out var symbolValue)
            || !reader.TryReadUInt64(out var symbolSize))
        {
            return false;
        }

        row = new SemanticStaticFunctionPointerRelocationRow(
            relocationSectionIndex,
            new FileOffset(relocationSectionFileOffset),
            new VirtualAddress(relocationSectionAddress),
            symbolTableSectionIndex,
            targetSectionIndex,
            relocationSourceAddress,
            siteAddress,
            info,
            type,
            symbolIndex,
            addend,
            isPlt,
            symbolNameOffset,
            name,
            symbolInfo,
            symbolOther,
            symbolSectionIndex,
            symbolValue,
            symbolSize);
        return true;
    }

    private static bool TryReadTlsBinding(SnapshotReader reader, out TlsBinding? binding)
    {
        binding = null;
        if (!reader.TryReadByte(out var model)
            || !reader.TryReadByte(out var family)
            || !TryReadEntityId(reader, out var sourceIdentity)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadRange(reader, out var sequenceRange)
            || !reader.TryReadByte(out var resolverKind)
            || !TryReadOptionalTarget(reader, out var resolverTarget)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTlsInstructions, out var instructionCount))
        {
            return false;
        }

        var instructions = new List<TlsInstructionRecord>(instructionCount);
        for (var index = 0; index < instructionCount; index++)
        {
            if (!TryReadRange(reader, out var instructionRange)
                || !reader.TryReadUInt32(out var encoding)
                || !reader.TryReadUtf8String(out var mnemonic)
                || !reader.TryReadByte(out var role)
                || !TryReadTlsRegisters(reader, out var inputRegisters)
                || !TryReadTlsRegisters(reader, out var outputRegisters)
                || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumRegisterEffectsPerInstruction, out var effectCount))
            {
                return false;
            }

            var effects = new List<SemanticRegisterEffect>(effectCount);
            for (var effectIndex = 0; effectIndex < effectCount; effectIndex++)
            {
                if (!TryReadRegisterEffect(reader, out var effect))
                {
                    return false;
                }

                effects.Add(effect);
            }

            if (!reader.TryReadBool(out var isCall) || !reader.TryReadBool(out var isResolverCall))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(TlsInstructionRole), (TlsInstructionRole)role))
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The TLS instruction contains an unsupported role enum value.");
            }

            instructions.Add(new TlsInstructionRecord(
                instructionRange,
                encoding,
                mnemonic,
                (TlsInstructionRole)role,
                inputRegisters,
                outputRegisters,
                effects,
                isCall,
                isResolverCall));
        }

        if (!TryReadTlsModule(reader, out var module)
            || !TryReadOptionalTlsSymbol(reader, out var symbol)
            || !reader.TryReadInt64(out var addend)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTlsRelocationSites, out var siteCount))
        {
            return false;
        }

        var sites = new List<TlsRelocationSite>(siteCount);
        for (var index = 0; index < siteCount; index++)
        {
            if (!reader.TryReadByte(out var siteFamily)
                || !TryReadRange(reader, out var siteRange)
                || !TryReadRelocation(reader, out var relocation)
                || !reader.TryReadInt32(out var pairOrdinal)
                || !reader.TryReadBool(out var isGotOrDescriptorOwned))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(TlsRelocationFamily), (TlsRelocationFamily)siteFamily)
                || relocation is null)
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The TLS relocation site contains an unsupported family or missing binding.");
            }

            sites.Add(new TlsRelocationSite(
                (TlsRelocationFamily)siteFamily,
                siteRange,
                relocation,
                pairOrdinal,
                isGotOrDescriptorOwned));
        }

        TlsResolverCallBinding? resolverCall = null;
        if (!reader.TryReadBool(out var hasResolverCall))
        {
            return false;
        }

        if (hasResolverCall)
        {
            if (!TryReadRange(reader, out var resolverRange)
                || !TryReadRelocation(reader, out var resolverRelocation)
                || resolverRelocation is null)
            {
                return false;
            }

            resolverCall = new TlsResolverCallBinding(resolverRange, resolverRelocation);
        }

        TlsModuleOwnerBinding? moduleOwner = null;
        if (!reader.TryReadBool(out var hasModuleOwner))
        {
            return false;
        }

        if (hasModuleOwner)
        {
            if (!TryReadEntityId(reader, out var ownerIdentity)
                || !TryReadRange(reader, out var ownerRange)
                || !TryReadRelocation(reader, out var ownerRelocation)
                || ownerRelocation is null)
            {
                return false;
            }

            moduleOwner = new TlsModuleOwnerBinding(ownerIdentity, ownerRange, ownerRelocation);
        }

        TlsDtpRelOwnerBinding? dtpRelOwner = null;
        if ((TlsAccessModel)model == TlsAccessModel.GeneralDynamic)
        {
            if (!reader.TryReadBool(out var hasDtpRelOwner))
            {
                return false;
            }

            if (hasDtpRelOwner)
            {
                if (!TryReadEntityId(reader, out var ownerIdentity)
                    || !TryReadRange(reader, out var ownerRange)
                    || !TryReadRelocation(reader, out var ownerRelocation)
                    || ownerRelocation is null)
                {
                    return false;
                }

                dtpRelOwner = new TlsDtpRelOwnerBinding(ownerIdentity, ownerRange, ownerRelocation);
            }
        }

        TlsGotEntryBinding? gotEntry = null;
        if ((TlsAccessModel)model == TlsAccessModel.InitialExec)
        {
            if (!reader.TryReadBool(out var hasGotEntry))
            {
                return false;
            }

            if (hasGotEntry && !TryReadTlsGotEntry(reader, out gotEntry))
            {
                return false;
            }
        }

        TlsDescriptorOwnerBinding? descriptorOwner = null;
        if ((TlsAccessModel)model == TlsAccessModel.TlsDesc)
        {
            if (!reader.TryReadBool(out var hasDescriptorOwner))
            {
                return false;
            }

            if (hasDescriptorOwner && !TryReadTlsDescriptorOwner(reader, out descriptorOwner))
            {
                return false;
            }
        }

        if (!reader.TryReadInt32(out var accessSize)
            || !reader.TryReadByte(out var expressionKind)
            || !TryReadTlsModule(reader, out var expressionModule)
            || !TryReadOptionalTlsSymbol(reader, out var expressionSymbol)
            || !TryReadOptionalRegister(reader, out var baseRegister)
            || !TryReadOptionalRegister(reader, out var valueRegister)
            || !reader.TryReadInt64(out var expressionAddend)
            || !reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTlsRequirements, out var profileCount))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(TlsAccessModel), (TlsAccessModel)model)
            || !Enum.IsDefined(typeof(TlsRelocationFamily), (TlsRelocationFamily)family)
            || !Enum.IsDefined(typeof(TlsResolverKind), (TlsResolverKind)resolverKind)
            || !Enum.IsDefined(typeof(TlsAddressExpressionKind), (TlsAddressExpressionKind)expressionKind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The TLS binding contains an unsupported model, family, resolver, or address expression enum value.");
        }

        var profiles = new List<TlsProfileRequirement>(profileCount);
        for (var index = 0; index < profileCount; index++)
        {
            if (!reader.TryReadByte(out var profile)
                || !reader.TryReadBool(out var required))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(TlsProfile), (TlsProfile)profile))
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The TLS binding contains an unsupported profile requirement.");
            }

            profiles.Add(new TlsProfileRequirement((TlsProfile)profile, required));
        }

        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumTlsRequirements, out var runtimeCount))
        {
            return false;
        }

        var runtimes = new List<TlsRuntimeRequirement>(runtimeCount);
        for (var index = 0; index < runtimeCount; index++)
        {
            if (!reader.TryReadByte(out var runtime)
                || !reader.TryReadByte(out var requirement)
                || !reader.TryReadBool(out var required))
            {
                return false;
            }

            if (!Enum.IsDefined(typeof(TlsRuntime), (TlsRuntime)runtime)
                || !Enum.IsDefined(typeof(TlsRuntimeRequirementKind), (TlsRuntimeRequirementKind)requirement))
            {
                return reader.Fail(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    "The TLS binding contains an unsupported runtime or runtime requirement.");
            }

            runtimes.Add(new TlsRuntimeRequirement(
                (TlsRuntime)runtime,
                (TlsRuntimeRequirementKind)requirement,
                required));
        }

        binding = new TlsBinding(
            (TlsAccessModel)model,
            (TlsRelocationFamily)family,
            sourceIdentity,
            sourceRange,
            new TlsInstructionSequence(
                sequenceRange,
                instructions,
                (TlsResolverKind)resolverKind,
                resolverTarget),
            module!,
            symbol,
            addend,
            sites,
            accessSize,
            new TlsAddressExpression(
                (TlsAddressExpressionKind)expressionKind,
                expressionModule!,
                expressionSymbol,
                baseRegister,
                valueRegister,
                expressionAddend),
            profiles,
            runtimes,
            gotEntry,
            resolverCall,
            moduleOwner,
            dtpRelOwner,
            descriptorOwner);
        return true;
    }

    private static bool TryReadTlsDescriptorOwner(
        SnapshotReader reader,
        out TlsDescriptorOwnerBinding? owner)
    {
        owner = null;
        if (!TryReadEntityId(reader, out var sourceIdentity)
            || !TryReadRange(reader, out var descriptorRange)
            || !TryReadRelocation(reader, out var relocation)
            || !TryReadOptionalTlsSymbol(reader, out var symbol)
            || !reader.TryReadInt64(out var addend)
            || !reader.TryReadUInt64(out var descriptorPlt)
            || !reader.TryReadUInt64(out var descriptorGot)
            || !reader.TryReadUInt64(out var pltGot)
            || !TryReadRange(reader, out var resolverPltRange)
            || !TryReadRange(reader, out var resolverGotRange)
            || relocation is null
            || symbol is null)
        {
            return false;
        }

        owner = new TlsDescriptorOwnerBinding(
            sourceIdentity,
            descriptorRange,
            relocation,
            symbol,
            addend,
            new VirtualAddress(descriptorPlt),
            new VirtualAddress(descriptorGot),
            new VirtualAddress(pltGot),
            resolverPltRange,
            resolverGotRange);
        return true;
    }


    private static bool TryReadTlsGotEntry(
        SnapshotReader reader,
        out TlsGotEntryBinding? gotEntry)
    {
        gotEntry = null;
        if (!TryReadEntityId(reader, out var sourceIdentity)
            || !TryReadRange(reader, out var sourceRange)
            || !TryReadRelocation(reader, out var relocation)
            || !TryReadOptionalTlsSymbol(reader, out var symbol)
            || !reader.TryReadInt64(out var addend)
            || relocation is null
            || symbol is null)
        {
            return false;
        }

        gotEntry = new TlsGotEntryBinding(
            sourceIdentity,
            sourceRange,
            relocation,
            symbol,
            addend);
        return true;
    }

    private static bool TryReadTlsRegisters(
        SnapshotReader reader,
        out IReadOnlyList<Aarch64RegisterView> registers)
    {
        registers = Array.Empty<Aarch64RegisterView>();
        if (!reader.TryReadCount(SemanticPlanSnapshotLimits.MaximumCandidates, out var count))
        {
            return false;
        }

        var values = new List<Aarch64RegisterView>(count);
        for (var index = 0; index < count; index++)
        {
            if (!TryReadRegister(reader, out var register))
            {
                return false;
            }

            values.Add(register);
        }

        registers = Array.AsReadOnly(values.ToArray());
        return true;
    }

    private static bool TryReadTlsModule(SnapshotReader reader, out TlsModuleIdentity? module)
    {
        module = null;
        if (!reader.TryReadByte(out var kind)
            || !reader.TryReadUtf8String(out var identity)
            || !reader.TryReadOptionalString(out var soname)
            || !TryReadOptionalUInt32(reader, out var runtimeModuleIndex)
            || !reader.TryReadBool(out var hasTemplate))
        {
            return false;
        }

        TlsTemplateContract? template = null;
        if (hasTemplate)
        {
            if (!TryReadTlsTemplate(reader, out template))
            {
                return false;
            }
        }

        if (!Enum.IsDefined(typeof(TlsModuleIdentityKind), (TlsModuleIdentityKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The TLS module identity contains an unsupported identity kind.");
        }

        module = new TlsModuleIdentity(
            (TlsModuleIdentityKind)kind,
            identity,
            soname,
            runtimeModuleIndex,
            template);
        return true;
    }

    private static bool TryReadTlsTemplate(SnapshotReader reader, out TlsTemplateContract? template)
    {
        template = null;
        if (!reader.TryReadUInt64(out var fileOffset)
            || !reader.TryReadUInt64(out var virtualAddress)
            || !reader.TryReadUInt64(out var fileSize)
            || !reader.TryReadUInt64(out var memorySize)
            || !reader.TryReadUInt64(out var alignment)
            || !reader.TryReadUInt32(out var permissions)
            || !reader.TryReadInt32(out var owningLoadIndex)
            || !reader.TryReadUtf8String(out var templateDigest))
        {
            return false;
        }

        template = new TlsTemplateContract(
            new FileOffset(fileOffset),
            new VirtualAddress(virtualAddress),
            fileSize,
            memorySize,
            alignment,
            permissions,
            owningLoadIndex,
            templateDigest);
        return true;
    }

    private static bool TryReadOptionalTlsSymbol(SnapshotReader reader, out TlsSymbolIdentity? symbol)
    {
        symbol = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadUInt32(out var index)
            || !reader.TryReadUtf8String(out var name)
            || !reader.TryReadByte(out var binding)
            || !reader.TryReadByte(out var type)
            || !reader.TryReadByte(out var visibility)
            || !reader.TryReadUInt16(out var sectionIndex)
            || !reader.TryReadUInt64(out var value)
            || !reader.TryReadUInt64(out var size)
            || !reader.TryReadBool(out var defined))
        {
            return false;
        }

        symbol = new TlsSymbolIdentity(
            index,
            name,
            binding,
            type,
            visibility,
            sectionIndex,
            value,
            size,
            defined);
        return true;
    }

    private static bool TryReadDiagnostic(
        SnapshotReader reader,
        out Diagnostic diagnostic)
    {
        diagnostic = default;
        ulong offset = 0;
        if (!reader.TryReadByte(out var severity)
            || !reader.TryReadUInt32(out var code)
            || !reader.TryReadBool(out var hasOffset)
            || (hasOffset && !reader.TryReadUInt64(out offset))
            || !reader.TryReadUtf8String(out var message))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(DiagnosticSeverity), (DiagnosticSeverity)severity)
            || code > int.MaxValue
            || !Enum.IsDefined(typeof(DiagnosticCode), (DiagnosticCode)code))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported diagnostic enum value.");
        }

        diagnostic = new Diagnostic(
            (DiagnosticSeverity)severity,
            (DiagnosticCode)code,
            message,
            hasOffset ? offset : null);
        return true;
    }

    private static bool TryReadEntityId(
        SnapshotReader reader,
        out SemanticEntityId identity)
    {
        identity = default;
        if (!reader.TryReadByte(out var kind)
            || !reader.TryReadUtf8String(out var value))
        {
            return false;
        }

        if (!Enum.IsDefined(typeof(SemanticEntityKind), (SemanticEntityKind)kind))
        {
            return reader.Fail(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported entity kind.");
        }

        identity = new SemanticEntityId((SemanticEntityKind)kind, value);
        return true;
    }

    private static bool TryReadOptionalEntityId(
        SnapshotReader reader,
        out SemanticEntityId? identity)
    {
        identity = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadEntityId(reader, out var value))
        {
            return false;
        }

        identity = value;
        return true;
    }

    private static bool TryReadRange(
        SnapshotReader reader,
        out SemanticSourceRange range)
    {
        range = default;
        if (!reader.TryReadUInt64(out var fileOffset)
            || !reader.TryReadUInt64(out var virtualAddress)
            || !reader.TryReadUInt64(out var size))
        {
            return false;
        }

        range = new SemanticSourceRange(
            new FileOffset(fileOffset),
            new VirtualAddress(virtualAddress),
            size);
        return true;
    }

    private static bool TryReadOptionalRange(
        SnapshotReader reader,
        out SemanticSourceRange? range)
    {
        range = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!TryReadRange(reader, out var value))
        {
            return false;
        }

        range = value;
        return true;
    }

    private static bool TryReadOptionalInt64(
        SnapshotReader reader,
        out long? value)
    {
        value = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadInt64(out var actual))
        {
            return false;
        }

        value = actual;
        return true;
    }

    private static bool TryReadOptionalUInt32(
        SnapshotReader reader,
        out uint? value)
    {
        value = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadUInt32(out var actual))
        {
            return false;
        }

        value = actual;
        return true;
    }

    private static bool TryReadOptionalUInt64(
        SnapshotReader reader,
        out ulong? value)
    {
        value = null;
        if (!reader.TryReadBool(out var present))
        {
            return false;
        }

        if (!present)
        {
            return true;
        }

        if (!reader.TryReadUInt64(out var actual))
        {
            return false;
        }

        value = actual;
        return true;
    }
}
