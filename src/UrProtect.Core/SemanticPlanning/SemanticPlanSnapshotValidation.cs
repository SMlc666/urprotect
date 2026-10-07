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
    private static bool ValidateCount(
        int count,
        int maximum,
        string name,
        DiagnosticBag diagnostics)
    {
        if (count >= 0 && count <= maximum)
        {
            return true;
        }

        diagnostics.Error(
            DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
            $"The semantic-plan snapshot contains too many {name} records (maximum {maximum}).");
        return false;
    }

    private static void ValidateAddressMapEntry(
        AddressMapEntry? entry,
        DiagnosticBag diagnostics)
    {
        if (entry is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null address-map entry.");
            return;
        }

        ValidateEntityId(entry.Identity, "address-map source identity", diagnostics);
        if (entry.OutputIdentity is { } outputIdentity)
        {
            ValidateEntityId(outputIdentity, "address-map output identity", diagnostics);
        }

        ValidateRange(entry.SourceRange, "address-map source", diagnostics);
        ValidateRange(entry.OutputRange, "address-map output", diagnostics);
    }

    private static void ValidateInstruction(
        SemanticInstruction? instruction,
        DiagnosticBag diagnostics)
    {
        if (instruction is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null semantic instruction.");
            return;
        }

        ValidateString(instruction.Mnemonic, "instruction mnemonic", false, diagnostics);
        ValidateRange(instruction.SourceRange, "instruction source", diagnostics);
        if (instruction.SourceRange.FileOffset != instruction.SourceFileOffset
            || instruction.SourceRange.VirtualAddress != instruction.SourceVirtualAddress
            || !instruction.SourceRange.IsInstructionRange)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic instruction does not carry a matching aligned source range.",
                instruction.SourceFileOffset.Value);
        }

        ValidateCount(
            instruction.Operands.Count,
            SemanticPlanSnapshotLimits.MaximumOperandsPerInstruction,
            "instruction operand",
            diagnostics);
        foreach (var operand in instruction.Operands)
        {
            ValidateOperand(operand, diagnostics, instruction.SourceFileOffset.Value);
        }

        ValidateCount(
            instruction.RegisterEffects.Count,
            SemanticPlanSnapshotLimits.MaximumRegisterEffectsPerInstruction,
            "instruction register-effect",
            diagnostics);
        foreach (var effect in instruction.RegisterEffects)
        {
            ValidateRegisterEffect(effect, diagnostics, instruction.SourceFileOffset.Value);
        }

        const SemanticFlagEffects knownFlags = SemanticFlagEffects.ReadNzcv | SemanticFlagEffects.WriteNzcv;
        if ((instruction.FlagEffects & ~knownFlags) != SemanticFlagEffects.None)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic instruction contains unsupported flag-effect bits.",
                instruction.SourceFileOffset.Value);
        }

        if (!Enum.IsDefined(typeof(Aarch64ControlFlowKind), instruction.ControlFlow))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic instruction contains an unsupported control-flow kind.",
                instruction.SourceFileOffset.Value);
        }

        ValidateTarget(instruction.ControlFlowTarget, "instruction control-flow target", diagnostics, instruction.SourceFileOffset.Value);
        ValidateExpression(instruction.PcRelativeExpression, diagnostics, instruction.SourceFileOffset.Value);
        ValidateLiteral(instruction.LiteralReference, diagnostics, instruction.SourceFileOffset.Value);

        ValidateCount(
            instruction.Relocations.Count,
            SemanticPlanSnapshotLimits.MaximumRelocationsPerInstruction,
            "instruction relocation",
            diagnostics);
        foreach (var relocation in instruction.Relocations)
        {
            ValidateRelocation(relocation, diagnostics, instruction.SourceFileOffset.Value);
        }

        ValidateCount(
            instruction.References.Count,
            SemanticPlanSnapshotLimits.MaximumReferencesPerInstruction,
            "instruction reference",
            diagnostics);
        foreach (var reference in instruction.References)
        {
            ValidateReference(reference, diagnostics, instruction.SourceFileOffset.Value);
        }
    }

    private static void ValidateOperand(
        SemanticOperand? operand,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (operand is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic instruction contains a null operand.",
                offset);
            return;
        }

        ValidateString(operand.Name, "operand name", false, diagnostics, offset);
        ValidateString(operand.Codec, "operand codec", false, diagnostics, offset);
        ValidateOptionalString(operand.TiedTo, "operand tie", diagnostics, offset);
        ValidateString(operand.SemanticDomain, "operand semantic domain", false, diagnostics, offset);
        if (!Enum.IsDefined(typeof(Aarch64OperandKind), operand.Kind)
            || !Enum.IsDefined(typeof(Aarch64OperandDirection), operand.Direction))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic operand contains an unsupported operand enum value.",
                offset);
        }

        ValidateRegisterConstraint(operand.RegisterConstraint, diagnostics, offset);
        if (operand.Register is { } register)
        {
            ValidateRegister(register, diagnostics, offset);
        }

        ValidateCount(
            operand.Registers.Count,
            SemanticPlanSnapshotLimits.MaximumCandidates,
            "operand register",
            diagnostics);
        foreach (var listRegister in operand.Registers)
        {
            ValidateRegister(listRegister, diagnostics, offset);
        }

        if (operand.Memory is { } memory)
        {
            ValidateRegister(memory.Base, diagnostics, offset);
            if (memory.Index is { } index)
            {
                ValidateRegister(index, diagnostics, offset);
            }

            ValidateString(memory.AddressingMode, "memory addressing mode", false, diagnostics, offset);
            ValidateString(memory.Ordering, "memory ordering", false, diagnostics, offset);
            if (memory.AccessSize <= 0 || memory.AccessSize > 4096)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A semantic memory operand has an invalid access size.",
                    offset);
            }
        }

        ValidatePositiveWidth(operand.RegisterWidth, "operand register width", diagnostics, offset);
        ValidatePositiveWidth(operand.FieldWidth, "operand field width", diagnostics, offset);
        ValidatePositiveWidth(operand.ElementWidth, "operand element width", diagnostics, offset);
    }

    private static void ValidateRegisterConstraint(
        Aarch64RegisterConstraint constraint,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (constraint.MinimumIndex < 0
            || constraint.MaximumIndex < constraint.MinimumIndex
            || constraint.MaximumIndex > 31
            || constraint.Step < 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic operand register constraint is outside the bounded AArch64 register domain.",
                offset);
        }
    }

    private static void ValidateRegisterEffect(
        SemanticRegisterEffect effect,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        ValidateRegister(effect.Register, diagnostics, offset);
        if (!Enum.IsDefined(typeof(SemanticRegisterEffectKind), effect.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic register effect contains an unsupported effect kind.",
                offset);
        }
    }

    private static void ValidateRegister(
        Aarch64RegisterView register,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (!Enum.IsDefined(typeof(Aarch64RegisterClass), register.Class)
            || !Enum.IsDefined(typeof(Aarch64RegisterRole), register.Role)
            || register.Index > 31
            || register.Width == 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic register view is outside the bounded AArch64 register domain.",
                offset);
        }
    }

    private static void ValidatePositiveWidth(
        int width,
        string name,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (width <= 0 || width > 4096)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"A {name} is outside the bounded width domain.",
                offset);
        }
    }

    private static void ValidateExpression(
        PcRelativeExpression? expression,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (expression is null)
        {
            return;
        }

        if (!Enum.IsDefined(typeof(PcRelativeExpressionKind), expression.Kind)
            || expression.Scale <= 0)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A PC-relative expression has an unsupported kind or scale.",
                offset);
        }

        ValidateTarget(expression.Target, "PC-relative expression target", diagnostics, offset, required: true);
    }

    private static void ValidateLiteral(
        LiteralReference? literal,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (literal is null)
        {
            return;
        }

        if (literal.AccessSize <= 0 || literal.AccessSize > 4096)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A literal reference has an invalid access size.",
                offset);
        }

        ValidateTarget(literal.Target, "literal target", diagnostics, offset, required: true);
        if (literal.PoolRange is { } poolRange)
        {
            ValidateRange(poolRange, "literal pool", diagnostics, offset);
        }
    }

    private static void ValidateReference(
        SemanticReference? reference,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (reference is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic instruction contains a null reference.",
                offset);
            return;
        }

        if (!Enum.IsDefined(typeof(SemanticReferenceKind), reference.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic reference contains an unsupported reference kind.",
                offset);
        }

        ValidateTarget(reference.Target, "semantic reference target", diagnostics, offset, required: true);
        ValidateExpression(reference.PcRelative, diagnostics, offset);
        ValidateLiteral(reference.Literal, diagnostics, offset);
        ValidateRelocation(reference.Relocation, diagnostics, offset);
        ValidateOptionalString(reference.Description, "reference description", diagnostics, offset);
    }

    private static void ValidateFixup(
        SemanticFixup? fixup,
        DiagnosticBag diagnostics)
    {
        if (fixup is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null fixup.");
            return;
        }

        var offset = fixup.SourceFileOffset.Value;
        if (!Enum.IsDefined(typeof(SemanticFixupKind), fixup.Kind)
            || !Enum.IsDefined(typeof(SemanticRelaxationKind), fixup.Relaxation))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A semantic fixup contains an unsupported kind or relaxation.",
                offset);
        }

        ValidateRange(fixup.SourceRange, "fixup source", diagnostics, offset);
        if (fixup.SourceRange.FileOffset != fixup.SourceFileOffset
            || fixup.SourceRange.VirtualAddress != fixup.SourceAddress)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A semantic fixup does not carry a matching source range.",
                offset);
        }

        if (fixup.Kind != SemanticFixupKind.Relocation && !fixup.SourceRange.IsInstructionRange)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "An instruction fixup does not cover one aligned AArch64 instruction.",
                offset);
        }

        ValidateTarget(fixup.Target, "fixup target", diagnostics, offset, required: true);
        ValidateExpression(fixup.Expression, diagnostics, offset);
        ValidateRelocation(fixup.Relocation, diagnostics, offset);
        ValidateCount(
            fixup.RelaxationOptions.Count,
            SemanticPlanSnapshotLimits.MaximumRelaxationOptions,
            "fixup relaxation option",
            diagnostics);
        var relaxationOptions = new HashSet<SemanticRelaxationKind>();
        foreach (var option in fixup.RelaxationOptions)
        {
            if (!Enum.IsDefined(typeof(SemanticRelaxationKind), option)
                || !relaxationOptions.Add(option))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A semantic fixup contains duplicate or unsupported relaxation options.",
                    offset);
            }
        }

        if (fixup.Kind == SemanticFixupKind.Relocation && fixup.Relocation is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A relocation fixup has no relocation binding.",
                offset);
        }

        if (fixup.Kind != SemanticFixupKind.Relocation && fixup.Expression is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A PC-relative fixup has no PC-relative expression.",
                offset);
        }
    }

    private static void ValidateRelocation(
        RelocationBinding? relocation,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (relocation is null)
        {
            return;
        }

        if (!Enum.IsDefined(typeof(Aarch64RelocationKind), relocation.Kind)
            || !relocation.IsKindConsistent)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A relocation binding has an unsupported or inconsistent raw AArch64 type/info pair.",
                offset);
        }

        ValidateTarget(relocation.Target, "relocation target", diagnostics, offset, required: true);
        ValidateOptionalString(relocation.SymbolName, "relocation symbol", diagnostics, offset);
    }

    private static void ValidateTarget(
        SemanticTarget? target,
        string name,
        DiagnosticBag diagnostics,
        ulong offset,
        bool required = false)
    {
        if (target is null)
        {
            if (required)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"A {name} is null.",
                    offset);
            }

            return;
        }

        if (!Enum.IsDefined(typeof(SemanticTargetResolution), target.Resolution))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                $"A {name} has an unsupported resolution state.",
                offset);
        }

        if (target.Identity is { } identity)
        {
            ValidateEntityId(identity, $"{name} identity", diagnostics, offset);
        }

        ValidateCount(
            target.CandidateIdentities.Count,
            SemanticPlanSnapshotLimits.MaximumCandidates,
            $"{name} candidate identity",
            diagnostics);
        var candidateIdentities = new HashSet<SemanticEntityId>();
        foreach (var candidateIdentity in target.CandidateIdentities)
        {
            ValidateEntityId(candidateIdentity, $"{name} candidate identity", diagnostics, offset);
            if (!candidateIdentities.Add(candidateIdentity))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"A {name} contains duplicate candidate identities.",
                    offset);
            }
        }

        ValidateCount(
            target.CandidateAddresses.Count,
            SemanticPlanSnapshotLimits.MaximumCandidates,
            $"{name} candidate address",
            diagnostics);
        var candidateAddresses = new HashSet<VirtualAddress>();
        foreach (var candidateAddress in target.CandidateAddresses)
        {
            if (!candidateAddresses.Add(candidateAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"A {name} contains duplicate candidate addresses.",
                    offset);
            }
        }

        ValidateOptionalString(target.RuntimeBinding, $"{name} runtime binding", diagnostics, offset);
        ValidateOptionalString(target.Diagnostic, $"{name} diagnostic", diagnostics, offset);
        switch (target.Resolution)
        {
            case SemanticTargetResolution.Exact
                when target.SourceAddress is null && target.Identity is null:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"An exact {name} has neither a source address nor an entity identity.",
                    offset);
                break;
            case SemanticTargetResolution.BoundedSet
                when target.CandidateAddresses.Count == 0 && target.CandidateIdentities.Count == 0:
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"A bounded {name} has no candidates.",
                    offset);
                break;
            case SemanticTargetResolution.RuntimeResolved
                when string.IsNullOrWhiteSpace(target.RuntimeBinding):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"A runtime-resolved {name} has no binding identity.",
                    offset);
                break;
            case SemanticTargetResolution.Unresolved
                when string.IsNullOrWhiteSpace(target.Diagnostic):
                diagnostics.Error(
                    DiagnosticCode.SemanticTargetUnresolved,
                    $"An unresolved {name} has no diagnostic.",
                    offset);
                break;
        }
    }

    private static void ValidateExtension(
        ISemanticPlanExtension? extension,
        HashSet<string> extensionKeys,
        DiagnosticBag diagnostics)
    {
        if (extension is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null extension.");
            return;
        }

        if (!Enum.IsDefined(typeof(SemanticPlanExtensionKind), extension.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported extension kind.");
            return;
        }

        var key = GetExtensionIdentityKey(extension);
        if (!extensionKeys.Add(key))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains duplicate extension identities.");
        }

        switch (extension)
        {
            case SemanticIndirectTargetExtension indirect:
                ValidateEntityId(indirect.SourceInstruction, "indirect-target source identity", diagnostics, indirect.SourceAddress.Value);
                ValidateTarget(indirect.Target, "indirect-target target", diagnostics, indirect.SourceAddress.Value, required: true);
                ValidateString(indirect.Diagnostic, "indirect-target diagnostic", false, diagnostics, indirect.SourceAddress.Value);
                break;
            case SemanticUnresolvedReferenceExtension unresolved:
                ValidateEntityId(unresolved.SourceInstruction, "unresolved-reference source identity", diagnostics, unresolved.SourceAddress.Value);
                ValidateTarget(unresolved.Target, "unresolved-reference target", diagnostics, unresolved.SourceAddress.Value, required: true);
                ValidateString(unresolved.Diagnostic, "unresolved-reference diagnostic", false, diagnostics, unresolved.SourceAddress.Value);
                if (!Enum.IsDefined(typeof(SemanticReferenceKind), unresolved.ReferenceKind))
                {
                    diagnostics.Error(
                        DiagnosticCode.SemanticPlanSnapshotUnsupported,
                        "An unresolved-reference extension has an unsupported reference kind.",
                        unresolved.SourceAddress.Value);
                }

                break;
            case SemanticRelocationBindingExtension relocation:
                ValidateEntityId(relocation.RelocationSite, "relocation-extension site identity", diagnostics);
                ValidateRelocation(relocation.Binding, diagnostics, relocation.Binding.RelocationAddress?.Value ?? 0);
                ValidateString(relocation.Diagnostic, "relocation-extension diagnostic", false, diagnostics);
                break;
            case SemanticTlsBindingExtension tls:
                ValidateEntityId(tls.SourceIdentity, "TLS source identity", diagnostics);
                ValidateRange(tls.SourceRange, "TLS source", diagnostics);
                ValidateRelocation(tls.Binding, diagnostics, tls.SourceRange.FileOffset.Value);
                ValidateString(tls.Model, "TLS model", false, diagnostics);
                ValidateOptionalString(tls.Diagnostic, "TLS diagnostic", diagnostics);
                break;
            case SemanticJumpTableExtension jumpTable:
                ValidateEntityId(jumpTable.TableIdentity, "jump-table identity", diagnostics);
                ValidateRange(jumpTable.TableRange, "jump-table range", diagnostics);
                ValidatePositiveWidth(jumpTable.EntrySize, "jump-table entry size", diagnostics, jumpTable.TableRange.FileOffset.Value);
                ValidateOptionalString(jumpTable.Encoding, "jump-table encoding", diagnostics);
                ValidateCount(
                    jumpTable.Targets.Count,
                    SemanticPlanSnapshotLimits.MaximumTargetsPerJumpTable,
                    "jump-table target",
                    diagnostics);
                foreach (var target in jumpTable.Targets)
                {
                    ValidateTarget(target, "jump-table target", diagnostics, jumpTable.TableRange.FileOffset.Value, required: true);
                }

                break;
            case SemanticCfiEffectExtension cfi:
                ValidateEntityId(cfi.SourceIdentity, "CFI source identity", diagnostics);
                ValidateRange(cfi.SourceRange, "CFI source", diagnostics);
                ValidateString(cfi.Effect, "CFI effect", false, diagnostics);
                ValidateCount(
                    cfi.RegisterEffects.Count,
                    SemanticPlanSnapshotLimits.MaximumCfiRegisterEffects,
                    "CFI register effect",
                    diagnostics);
                foreach (var effect in cfi.RegisterEffects)
                {
                    ValidateRegisterEffect(effect, diagnostics, cfi.SourceRange.FileOffset.Value);
                }

                ValidateOptionalString(cfi.Diagnostic, "CFI diagnostic", diagnostics);
                break;
            default:
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotUnsupported,
                    $"The semantic-plan extension type '{extension.GetType().Name}' has no canonical projection.");
                break;
        }
    }

    private static void ValidateDiagnostic(
        Diagnostic? diagnostic,
        DiagnosticBag diagnostics)
    {
        if (diagnostic is null)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "The semantic-plan snapshot contains a null diagnostic.");
            return;
        }

        var actual = diagnostic.Value;
        if (!Enum.IsDefined(typeof(DiagnosticSeverity), actual.Severity)
            || !Enum.IsDefined(typeof(DiagnosticCode), actual.Code))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "The semantic-plan snapshot contains an unsupported diagnostic enum value.");
        }

        ValidateString(actual.Message, "diagnostic message", false, diagnostics, actual.Offset);
    }

    private static void ValidateRange(
        SemanticSourceRange range,
        string name,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (range.Size == 0
            || !range.TryGetFileEnd(out _)
            || !range.TryGetVirtualEnd(out _))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"The {name} range is empty or overflows its typed address domains.",
                offset);
        }
    }

    private static void ValidateEntityId(
        SemanticEntityId identity,
        string name,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (!Enum.IsDefined(typeof(SemanticEntityKind), identity.Kind))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                $"The {name} has an unsupported entity kind.",
                offset);
        }

        if (string.IsNullOrWhiteSpace(identity.Value))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"The {name} must be non-empty.",
                offset);
            return;
        }

        ValidateString(identity.Value, name, false, diagnostics, offset);
    }

    private static void ValidateString(
        string? value,
        string name,
        bool allowNull,
        DiagnosticBag diagnostics,
        ulong? offset = null)
    {
        if (value is null)
        {
            if (!allowNull)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    $"The {name} is null.",
                    offset);
            }

            return;
        }

        try
        {
            if (StrictUtf8.GetByteCount(value) > SemanticPlanSnapshotLimits.MaximumStringBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                    $"The {name} exceeds the maximum UTF-8 metadata length.",
                    offset);
            }
        }
        catch (EncoderFallbackException)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                $"The {name} is not valid UTF-8 text.",
                offset);
        }
    }

    private static void ValidateOptionalString(
        string? value,
        string name,
        DiagnosticBag diagnostics,
        ulong? offset = null) =>
        ValidateString(value, name, true, diagnostics, offset);

    private static string GetExtensionIdentityKey(ISemanticPlanExtension extension) =>
        extension switch
        {
            SemanticIndirectTargetExtension indirect =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(indirect.SourceInstruction)
                + GetUlongSortKey(indirect.SourceAddress.Value),
            SemanticUnresolvedReferenceExtension unresolved =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(unresolved.SourceInstruction)
                + GetUlongSortKey(unresolved.SourceAddress.Value)
                + GetIntSortKey((int)unresolved.ReferenceKind),
            SemanticRelocationBindingExtension relocation =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(relocation.RelocationSite),
            SemanticTlsBindingExtension tls =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(tls.SourceIdentity),
            SemanticJumpTableExtension jumpTable =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(jumpTable.TableIdentity),
            SemanticCfiEffectExtension cfi =>
                GetIntSortKey((int)extension.Kind)
                + GetEntitySortKey(cfi.SourceIdentity),
            _ => GetIntSortKey((int)extension.Kind)
                + GetOptionalStringSortKey(extension.GetType().FullName),
        };

    private static string GetExtensionSortKey(ISemanticPlanExtension extension) =>
        GetExtensionIdentityKey(extension)
        + GetOptionalStringSortKey(extension.GetType().FullName);

    private sealed record CanonicalPlan(
        AddressMap AddressMap,
        IReadOnlyList<SemanticInstruction> Instructions,
        IReadOnlyList<SemanticFixup> Fixups,
        IReadOnlyList<ISemanticPlanExtension> Extensions,
        IReadOnlyList<Diagnostic> Diagnostics);

    private sealed class SnapshotEncodingException : Exception
    {
        public SnapshotEncodingException(string message, DiagnosticCode code)
            : base(message)
        {
            Code = code;
        }

        public DiagnosticCode Code { get; }
    }
}
