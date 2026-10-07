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
                ValidateTlsBinding(tls.Binding, diagnostics);
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

    private static void ValidateTlsBinding(TlsBinding binding, DiagnosticBag diagnostics)
    {
        var offset = binding.SourceRange.FileOffset.Value;
        if (!Enum.IsDefined(typeof(TlsAccessModel), binding.AccessModel)
            || !Enum.IsDefined(typeof(TlsRelocationFamily), binding.RelocationFamily)
            || !TlsRelocationClassifier.IsModelCompatible(binding.AccessModel, binding.RelocationFamily))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotUnsupported,
                "A TLS binding contains an unsupported or model-inconsistent access/relocation family.",
                offset);
        }

        ValidateEntityId(binding.SourceIdentity, "TLS source identity", diagnostics, offset);
        ValidateRange(binding.SourceRange, "TLS source sequence", diagnostics, offset);
        ValidateTlsModule(binding.Module, diagnostics, offset);
        ValidateTlsSymbol(binding.Symbol, binding.Module, diagnostics, offset);
        if (binding.AccessModel is TlsAccessModel.LocalExec or TlsAccessModel.InitialExec
            && (binding.Module.Kind != TlsModuleIdentityKind.ImageLocal
                || binding.Module.RuntimeModuleIndex is not null
                || binding.Module.Template is null
                || binding.Symbol is null
                || !binding.Symbol.IsDefined
                || binding.Symbol.SymbolType != ElfConstants.SttTls))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "A local-exec or initial-exec TLS binding requires a resolved image-local module and a defined STT_TLS symbol.",
                offset);
        }

        if (binding.SourceRange != binding.InstructionSequence.SourceRange
            || binding.SourceRange.VirtualAddress.Value % sizeof(uint) != 0
            || binding.SourceRange.Size % sizeof(uint) != 0)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS binding and instruction sequence do not identify the same aligned source range.",
                offset);
        }

        ValidateCount(
            binding.InstructionSequence.Instructions.Count,
            SemanticPlanSnapshotLimits.MaximumTlsInstructions,
            "TLS instruction",
            diagnostics);
        var sequence = binding.InstructionSequence;
        if (sequence.Instructions.Count == 0
            || !Enum.IsDefined(typeof(TlsResolverKind), sequence.ResolverKind))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "A TLS instruction sequence is empty or has an unsupported resolver kind.",
                offset);
        }

        var resolverCallCount = 0;
        var expectedSequenceSize = checked((ulong)sequence.Instructions.Count * sizeof(uint));
        if (binding.SourceRange.Size != expectedSequenceSize)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS instruction count does not cover exactly the declared source sequence range.",
                offset);
        }

        for (var index = 0; index < sequence.Instructions.Count; index++)
        {
            var instruction = sequence.Instructions[index];
            if (instruction is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "The TLS instruction sequence contains a null instruction.",
                    offset);
                continue;
            }

            var step = checked((ulong)index * sizeof(uint));
            var virtualRangeValid = TryAdd(binding.SourceRange.VirtualAddress.Value, step, out var expectedVirtual);
            var fileRangeValid = TryAdd(binding.SourceRange.FileOffset.Value, step, out var expectedFile);
            if (!virtualRangeValid || !fileRangeValid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "The TLS instruction sequence address arithmetic overflowed its typed source domain.",
                    offset);
            }

            if (!instruction.SourceRange.IsInstructionRange
                || instruction.SourceRange.Size != sizeof(uint)
                || !virtualRangeValid
                || !fileRangeValid
                || instruction.SourceRange.VirtualAddress.Value != expectedVirtual
                || instruction.SourceRange.FileOffset.Value != expectedFile
                || !Enum.IsDefined(typeof(TlsInstructionRole), instruction.Role))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "A TLS sequence contains a non-contiguous, unaligned, or unsupported instruction record.",
                    instruction.SourceRange.FileOffset.Value);
            }

            ValidateString(instruction.Mnemonic, "TLS instruction mnemonic", false, diagnostics, instruction.SourceRange.FileOffset.Value);
            ValidateCount(
                instruction.InputRegisters.Count,
                SemanticPlanSnapshotLimits.MaximumCandidates,
                "TLS input register",
                diagnostics);
            ValidateCount(
                instruction.OutputRegisters.Count,
                SemanticPlanSnapshotLimits.MaximumCandidates,
                "TLS output register",
                diagnostics);
            foreach (var register in instruction.InputRegisters.Concat(instruction.OutputRegisters))
            {
                ValidateRegister(register, diagnostics, instruction.SourceRange.FileOffset.Value);
            }

            ValidateCount(
                instruction.RegisterEffects.Count,
                SemanticPlanSnapshotLimits.MaximumRegisterEffectsPerInstruction,
                "TLS register effect",
                diagnostics);
            foreach (var effect in instruction.RegisterEffects)
            {
                ValidateRegisterEffect(effect, diagnostics, instruction.SourceRange.FileOffset.Value);
            }

            if (instruction.IsResolverCall)
            {
                resolverCallCount++;
                if (!instruction.IsCall)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsSequenceMalformed,
                        "A TLS resolver-call instruction is not marked as a call.",
                        instruction.SourceRange.FileOffset.Value);
                }
            }
        }

        var needsResolver = binding.AccessModel is TlsAccessModel.LocalDynamic
            or TlsAccessModel.GeneralDynamic
            or TlsAccessModel.TlsDesc;
        if ((needsResolver && (sequence.ResolverKind == TlsResolverKind.None
                || resolverCallCount != 1
                || sequence.ResolverTarget is null))
            || (!needsResolver && (sequence.ResolverKind != TlsResolverKind.None
                || resolverCallCount != 0
                || sequence.ResolverTarget is not null)))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS model and resolver call ownership are incomplete or inconsistent.",
                offset);
        }

        if (binding.AccessModel is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
            && sequence.ResolverKind != TlsResolverKind.TlsGetAddr
            || binding.AccessModel == TlsAccessModel.TlsDesc
                && sequence.ResolverKind != TlsResolverKind.TlsDesc)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS instruction sequence uses the wrong resolver family for its access model.",
                offset);
        }

        ValidateTarget(sequence.ResolverTarget, "TLS resolver target", diagnostics, offset);
        ValidateCount(
            binding.RelocationSites.Count,
            SemanticPlanSnapshotLimits.MaximumTlsRelocationSites,
            "TLS relocation site",
            diagnostics);
        var relocationSites = new HashSet<(VirtualAddress VirtualAddress, FileOffset FileOffset)>();
        var familySet = new HashSet<TlsRelocationFamily>();
        foreach (var site in binding.RelocationSites)
        {
            if (site is null || site.Binding is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "The TLS binding contains a null relocation site or relocation binding.",
                    offset);
                continue;
            }

            var relocationType = site.Binding.RelocationType;
            var writeSize = relocationType is { } type ? TlsRelocationClassifier.GetWriteSize(type) : 0;
            ValidateRange(site.SourceRange, "TLS relocation site", diagnostics, site.SourceRange.FileOffset.Value);
            if (!Enum.IsDefined(typeof(TlsRelocationFamily), site.Family)
                || !TlsRelocationClassifier.IsModelCompatible(binding.AccessModel, site.Family)
                || relocationType is null
                || TlsRelocationClassifier.GetFamily(relocationType.Value) != site.Family
                || (TlsRelocationClassifier.GetAccessModel(relocationType.Value) is { } inferredModel
                    && inferredModel != binding.AccessModel)
                || (binding.Symbol is not null
                    && (site.Binding.SymbolIndex != binding.Symbol.SymbolIndex
                        || !string.Equals(site.Binding.SymbolName, binding.Symbol.Name, StringComparison.Ordinal)))
                || writeSize == 0
                || site.SourceRange.Size != writeSize
                || site.SourceRange.FileOffset.Value % writeSize != 0
                || site.SourceRange.VirtualAddress.Value % writeSize != 0
                || site.PairOrdinal < 0
                || (site.Binding.RelocationAddress is { } siteAddress
                    && siteAddress != site.SourceRange.VirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "A TLS relocation site has an unsupported family, write range, pair identity, or model association.",
                    site.SourceRange.FileOffset.Value);
            }

            ValidateRelocation(site.Binding, diagnostics, site.SourceRange.FileOffset.Value);
            if (!relocationSites.Add((site.SourceRange.VirtualAddress, site.SourceRange.FileOffset)))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "A TLS binding contains duplicate relocation sites.",
                    site.SourceRange.FileOffset.Value);
            }

            familySet.Add(site.Family);
            if (relocationType is { } codeType
                && codeType < ElfConstants.RArm64TlsDtpMod64
                && !binding.InstructionSequence.Instructions.Any(instruction =>
                    instruction is not null
                    && instruction.SourceRange.VirtualAddress == site.SourceRange.VirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "A TLS instruction relocation site is not owned by the declared source instruction sequence.",
                    site.SourceRange.FileOffset.Value);
            }

            if (binding.AccessModel == TlsAccessModel.LocalExec && relocationType is { } localExecType)
            {
                var matchingInstructions = binding.InstructionSequence.Instructions
                    .Where(instruction => instruction is not null
                        && instruction.SourceRange.VirtualAddress == site.SourceRange.VirtualAddress)
                    .ToArray();
                if (matchingInstructions.Length != 1
                    || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(
                        localExecType,
                        matchingInstructions[0].Encoding))
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsSequenceMalformed,
                        "A local-exec TPREL relocation must own an instruction with the exact supported opcode and immediate shift in the canonical source sequence.",
                        site.SourceRange.FileOffset.Value);
                }
            }
        }

        if (!TlsRelocationClassifier.IsCompleteRelocationPattern(
                binding.AccessModel,
                binding.RelocationSites
                    .Where(site => site is not null
                        && site.Binding is not null
                        && site.Binding.RelocationType.HasValue)
                    .Select(site => site.Binding!.RelocationType!.Value)))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS binding omits one or more required relocation-family sites for its model.",
                offset);
        }

        var orderedLocalExecSites = binding.RelocationSites
            .Where(site => site is not null)
            .OrderBy(site => site.PairOrdinal)
            .ToArray();
        if (binding.AccessModel == TlsAccessModel.InitialExec
            && (binding.GotEntry is null
                || !IsValidInitialExecRelocationPair(binding, orderedLocalExecSites)))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The supported initial-exec snapshot requires one ordered TLSIE MOVW GOTTPREL G1/G0_NC pair and a validated GOT entry.",
                offset);
        }
        else if (binding.AccessModel == TlsAccessModel.LocalExec
            && !IsValidLocalExecRelocationPair(binding, orderedLocalExecSites))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The supported local-exec snapshot requires one ordered ADD HI12/LO12, ADD HI12/LDST32 LO12_NC, or MOVW G1/G0_NC pair with a resolved symbol and consistent addend.",
                offset);
        }

        if (!familySet.Contains(binding.RelocationFamily))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS binding's primary relocation family is absent from its typed relocation sites.",
                offset);
        }

        if (binding.AccessModel == TlsAccessModel.InitialExec
            && binding.GotEntry is { } gotEntry)
        {
            ValidateTlsGotEntry(gotEntry, binding.Module, binding.Symbol, binding.Addend, diagnostics, offset);
        }

        if (binding.AccessSize is not (1 or 2 or 4 or 8 or 16))
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotMalformed,
                "A TLS access width is outside the supported scalar/vector widths.",
                offset);
        }

        var expression = binding.AddressExpression;
        var expectedExpression = binding.AccessModel switch
        {
            TlsAccessModel.LocalExec or TlsAccessModel.InitialExec => TlsAddressExpressionKind.ThreadPointerRelative,
            TlsAccessModel.LocalDynamic => TlsAddressExpressionKind.ModuleRelative,
            TlsAccessModel.GeneralDynamic => TlsAddressExpressionKind.ResolverReturned,
            TlsAccessModel.TlsDesc => TlsAddressExpressionKind.DescriptorMediated,
            _ => (TlsAddressExpressionKind?)null,
        };
        if (!Enum.IsDefined(typeof(TlsAddressExpressionKind), expression.Kind)
            || expectedExpression is null
            || expectedExpression.Value != expression.Kind
            || expression.Module != binding.Module
            || expression.Symbol != binding.Symbol
            || expression.Addend != binding.Addend)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS address expression does not match the typed model, module, and symbol identities.",
                offset);
        }

        if (expression.BaseRegister is { } baseRegister)
        {
            ValidateRegister(baseRegister, diagnostics, offset);
        }

        if (expression.ValueRegister is { } valueRegister)
        {
            ValidateRegister(valueRegister, diagnostics, offset);
        }

        if (!Enum.IsDefined(typeof(TlsModuleIdentityKind), binding.Module.Kind)
            || string.IsNullOrWhiteSpace(binding.Module.Identity))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "The TLS module identity is missing or unsupported.",
                offset);
        }

        ValidateCount(
            binding.ProfileRequirements.Count,
            SemanticPlanSnapshotLimits.MaximumTlsRequirements,
            "TLS profile requirement",
            diagnostics);
        var profiles = new HashSet<TlsProfile>();
        foreach (var requirement in binding.ProfileRequirements)
        {
            if (requirement is null
                || !Enum.IsDefined(typeof(TlsProfile), requirement.Profile)
                || !profiles.Add(requirement.Profile))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A TLS profile requirement is unsupported or duplicated.",
                    offset);
            }
        }

        ValidateCount(
            binding.RuntimeRequirements.Count,
            SemanticPlanSnapshotLimits.MaximumTlsRequirements,
            "TLS runtime requirement",
            diagnostics);
        var runtimes = new HashSet<(TlsRuntime Runtime, TlsRuntimeRequirementKind Kind)>();
        foreach (var requirement in binding.RuntimeRequirements)
        {
            if (requirement is null
                || !Enum.IsDefined(typeof(TlsRuntime), requirement.Runtime)
                || !Enum.IsDefined(typeof(TlsRuntimeRequirementKind), requirement.Kind)
                || !runtimes.Add((requirement.Runtime, requirement.Kind)))
            {
                diagnostics.Error(
                    DiagnosticCode.SemanticPlanSnapshotMalformed,
                    "A TLS runtime requirement is unsupported or duplicated for its runtime.",
                    offset);
            }
        }

        ValidateModelSequenceRoles(binding, diagnostics);
    }

    private static bool IsValidInitialExecRelocationPair(
        TlsBinding binding,
        IReadOnlyList<TlsRelocationSite> sites)
    {
        return binding.GotEntry is not null
            && sites.Count == 2
            && sites[0].Binding.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG1
            && sites[1].Binding.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG0Nc
            && Aarch64TlsInstructionSemantics.IsSupportedInitialExecMovwPair(
                binding.InstructionSequence.Instructions,
                sites);
    }

    private static bool IsValidLocalExecRelocationPair(
        TlsBinding binding,
        IReadOnlyList<TlsRelocationSite> sites)
    {
        if (binding.Symbol is null
            || sites.Count != 2
            || sites[0].Binding is null
            || sites[1].Binding is null
            || sites[0].PairOrdinal != 0
            || sites[1].PairOrdinal != 1
            || sites[0].Binding.Addend != binding.Addend
            || sites[1].Binding.Addend != binding.Addend
            || sites[0].SourceRange.VirtualAddress.Value >= sites[1].SourceRange.VirtualAddress.Value
            || sites[0].SourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
            || sites[1].SourceRange.FileOffset.Value
                != sites[0].SourceRange.FileOffset.Value + sizeof(uint))
        {
            return false;
        }

        var firstType = sites[0].Binding.RelocationType.GetValueOrDefault();
        var secondType = sites[1].Binding.RelocationType.GetValueOrDefault();
        var isAddPair = firstType == ElfConstants.RArm64TlsLeAddTprelHi12
            && secondType is ElfConstants.RArm64TlsLeAddTprelLo12 or ElfConstants.RArm64TlsLeAddTprelLo12Nc;
        if (isAddPair)
        {
            return Aarch64TlsInstructionSemantics.IsSupportedLocalExecAddPair(instructions: binding.InstructionSequence.Instructions, relocationSites: sites);
        }

        var isLdst32Pair = firstType == ElfConstants.RArm64TlsLeAddTprelHi12
            && secondType == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc;
        if (isLdst32Pair)
        {
            return binding.Symbol is not null
                && Aarch64TlsInstructionSemantics.TryAddSigned(
                    binding.Symbol.Value,
                    binding.Addend,
                    out var tprelOffset)
                && Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                    binding.InstructionSequence.Instructions,
                    sites,
                    tprelOffset);
        }

        if (firstType != ElfConstants.RArm64TlsLeMovwTprelG1
            || secondType != ElfConstants.RArm64TlsLeMovwTprelG0Nc)
        {
            return false;
        }

        var instructions = binding.InstructionSequence.Instructions;
        var firstIndex = FindTlsInstructionIndex(instructions, sites[0].SourceRange.VirtualAddress);
        var secondIndex = FindTlsInstructionIndex(instructions, sites[1].SourceRange.VirtualAddress);
        if (firstIndex < 0
            || secondIndex != firstIndex + 1
            || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecMovwPair(
                firstType,
                instructions[firstIndex].Encoding,
                sites[0].SourceRange.VirtualAddress.Value,
                sites[0].Binding.Addend,
                secondType,
                instructions[secondIndex].Encoding,
                sites[1].SourceRange.VirtualAddress.Value,
                sites[1].Binding.Addend)
            || !Aarch64TlsInstructionSemantics.TryGetLocalExecMovwRegister(
                firstType,
                instructions[firstIndex].Encoding,
                out var tprelRegister))
        {
            return false;
        }

        var threadPointerInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => Aarch64TlsInstructionSemantics.TryGetThreadPointerRegister(
                item.instruction.Encoding,
                out _))
            .ToArray();
        if (threadPointerInstructions.Length != 1
            || !Aarch64TlsInstructionSemantics.TryGetThreadPointerRegister(
                threadPointerInstructions[0].instruction.Encoding,
                out var threadPointerRegister))
        {
            return false;
        }

        var threadPointerIndex = threadPointerInstructions[0].index;
        if (threadPointerIndex != firstIndex - 1
            && threadPointerIndex != secondIndex + 1)
        {
            return false;
        }

        // The TP read and MOVW pair must be distinct live values until ADD
        // consumes them. A register alias would make the address expression
        // semantically different from TP + TPREL.
        if (threadPointerRegister == tprelRegister)
        {
            return false;
        }

        var expectedAddIndex = Math.Max(secondIndex, threadPointerIndex) + 1;
        var addInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.index == expectedAddIndex
                && Aarch64TlsInstructionSemantics.TryGetLocalExecAddressRegister(
                    item.instruction.Encoding,
                    threadPointerRegister,
                    tprelRegister,
                    out _))
            .ToArray();
        if (addInstructions.Length != 1
            || !Aarch64TlsInstructionSemantics.TryGetLocalExecAddressRegister(
                addInstructions[0].instruction.Encoding,
                threadPointerRegister,
                tprelRegister,
                out var addressRegister))
        {
            return false;
        }

        var memoryAccesses = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.instruction.Role == TlsInstructionRole.TlsMemoryAccess)
            .ToArray();
        return memoryAccesses.Length == 1
            && memoryAccesses[0].index == addInstructions[0].index + 1
            && memoryAccesses[0].instruction.InputRegisters.Any(register =>
                register.Class == Aarch64RegisterClass.General
                && register.Role == Aarch64RegisterRole.None
                && register.Width == 64
                && register.Index == addressRegister);
    }

    private static int FindTlsInstructionIndex(
        IReadOnlyList<TlsInstructionRecord> instructions,
        VirtualAddress address) => instructions
        .Select((instruction, index) => (instruction, index))
        .Where(item => item.instruction is not null && item.instruction.SourceRange.VirtualAddress == address)
        .Select(item => item.index)
        .DefaultIfEmpty(-1)
        .First();

    private static void ValidateTlsGotEntry(
        TlsGotEntryBinding gotEntry,
        TlsModuleIdentity module,
        TlsSymbolIdentity? symbol,
        long addend,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        ValidateEntityId(gotEntry.SourceIdentity, "TLSIE GOT source identity", diagnostics, offset);
        ValidateRange(gotEntry.SourceRange, "TLSIE GOT source range", diagnostics, offset);
        ValidateRelocation(gotEntry.Relocation, diagnostics, offset);
        var valid = symbol is not null
            && gotEntry.Symbol == symbol
            && gotEntry.Addend == addend
            && gotEntry.SourceRange.Size == sizeof(ulong)
            && gotEntry.SourceRange.FileOffset.Value % sizeof(ulong) == 0
            && gotEntry.SourceRange.VirtualAddress.Value % sizeof(ulong) == 0
            && gotEntry.Relocation.RelocationType == ElfConstants.RArm64TlsTprel64
            && !gotEntry.Relocation.IsPlt
            && gotEntry.Relocation.Kind == Aarch64RelocationKind.ThreadLocal
            && gotEntry.Relocation.SymbolIndex == gotEntry.Symbol.SymbolIndex
            && string.Equals(gotEntry.Relocation.SymbolName, gotEntry.Symbol.Name, StringComparison.Ordinal)
            && gotEntry.Relocation.Addend == addend
            && gotEntry.Relocation.RelocationAddress == gotEntry.SourceRange.VirtualAddress
            && gotEntry.Relocation.Target.Resolution == SemanticTargetResolution.RuntimeResolved
            && string.Equals(
                gotEntry.Relocation.Target.RuntimeBinding,
                $"tls-got:{module.Identity}:{gotEntry.Symbol.Name}",
                StringComparison.Ordinal)
            && gotEntry.Relocation.IsKindConsistent;
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "The TLSIE GOT entry has an invalid source identity, relocation, module, symbol, range, or addend.",
                offset);
        }
    }

    private static void ValidateTlsModule(
        TlsModuleIdentity module,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (!Enum.IsDefined(typeof(TlsModuleIdentityKind), module.Kind)
            || string.IsNullOrWhiteSpace(module.Identity))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "A TLS module identity is missing or unsupported.",
                offset);
        }

        ValidateOptionalString(module.Soname, "TLS module SONAME", diagnostics, offset);
        if (module.Kind == TlsModuleIdentityKind.RuntimeAssigned && module.RuntimeModuleIndex is not null)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "A runtime-assigned TLS module number must remain unresolved in the semantic snapshot.",
                offset);
        }

        if (module.Template is { } template)
        {
            if (template.FileSize > template.MemorySize
                || template.MemorySize == 0
                || template.FileSize > ulong.MaxValue - template.FileOffset.Value
                || template.MemorySize > ulong.MaxValue - template.VirtualAddress.Value
                || template.OwningLoadProgramHeaderIndex < 0
                || template.Alignment > 1 && (!IsSnapshotPowerOfTwo(template.Alignment)
                    || template.FileOffset.Value % template.Alignment != template.VirtualAddress.Value % template.Alignment)
                || (template.Permissions & ElfConstants.PfR) == 0
                || (template.Permissions & ElfConstants.PfX) != 0
                || !IsSha256(template.InitializedTemplateSha256))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "The TLS template contract has an invalid size, owner, alignment, permission set, or digest.",
                    offset);
            }
        }
    }

    private static void ValidateTlsSymbol(
        TlsSymbolIdentity? symbol,
        TlsModuleIdentity module,
        DiagnosticBag diagnostics,
        ulong offset)
    {
        if (symbol is null)
        {
            return;
        }

        if (symbol.SymbolIndex == 0
            || string.IsNullOrWhiteSpace(symbol.Name)
            || symbol.SymbolType != ElfConstants.SttTls
            || symbol.Visibility > 3
            || symbol.IsDefined != (symbol.SectionIndex != 0))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "A TLS symbol identity is incomplete or inconsistent with its dynamic-symbol fields.",
                offset);
        }

        ValidateString(symbol.Name, "TLS symbol name", false, diagnostics, offset);
        if (symbol.IsDefined)
        {
            var template = module.Template;
            if (template is null
                || symbol.Value > template.MemorySize
                || symbol.Size > template.MemorySize - symbol.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsMetadataMalformed,
                    "A defined TLS symbol lies outside its PT_TLS template and zero-fill range.",
                    offset);
            }
        }
    }

    private static void ValidateModelSequenceRoles(TlsBinding binding, DiagnosticBag diagnostics)
    {
        var roles = binding.InstructionSequence.Instructions
            .Where(instruction => instruction is not null)
            .Select(instruction => instruction.Role)
            .ToHashSet();
        var valid = binding.AccessModel switch
        {
            TlsAccessModel.LocalExec => roles.Contains(TlsInstructionRole.ThreadPointerRead)
                && roles.Contains(TlsInstructionRole.AddressFormation)
                && roles.Contains(TlsInstructionRole.TlsMemoryAccess),
            TlsAccessModel.InitialExec => roles.Contains(TlsInstructionRole.AddressFormation)
                && roles.Contains(TlsInstructionRole.GotEntryLoad)
                && roles.Contains(TlsInstructionRole.ThreadPointerRead)
                && roles.Contains(TlsInstructionRole.TlsMemoryAccess),
            TlsAccessModel.LocalDynamic => roles.Contains(TlsInstructionRole.ModuleLookup)
                && roles.Contains(TlsInstructionRole.ResolverCall)
                && roles.Contains(TlsInstructionRole.SymbolOffsetFormation)
                && binding.RelocationSites.Any(site => site is not null && site.Family == TlsRelocationFamily.Dtpmod)
                && binding.RelocationSites.Any(site => site is not null && site.Family == TlsRelocationFamily.Dtprel),
            TlsAccessModel.GeneralDynamic => roles.Contains(TlsInstructionRole.ModuleLookup)
                && roles.Contains(TlsInstructionRole.ResolverCall)
                && binding.RelocationSites.Any(site => site is not null && site.Family == TlsRelocationFamily.Dtpmod)
                && binding.RelocationSites.Any(site => site is not null && site.Family == TlsRelocationFamily.Dtprel),
            TlsAccessModel.TlsDesc => roles.Contains(TlsInstructionRole.DescriptorLoad)
                && roles.Contains(TlsInstructionRole.DescriptorCall)
                && roles.Contains(TlsInstructionRole.AddressFinalization),
            _ => false,
        };
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS model's instruction sequence is incomplete or inconsistent with its relocation family.",
                binding.SourceRange.FileOffset.Value);
        }
    }

    private static bool IsSnapshotPowerOfTwo(ulong value) => value != 0 && (value & (value - 1)) == 0;

    private static bool TryAdd(ulong value, ulong amount, out ulong result)
    {
        if (amount > ulong.MaxValue - value)
        {
            result = 0;
            return false;
        }

        result = value + amount;
        return true;
    }

    private static bool IsSha256(string? value) => value is not null
        && value.Length == 64
        && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');

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
