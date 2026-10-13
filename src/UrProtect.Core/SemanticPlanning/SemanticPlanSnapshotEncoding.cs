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
    private static void WriteAddressMapEntry(CanonicalWriteContext context, AddressMapEntry entry)
    {
        WriteEntityId(context, entry.Identity);
        WriteOptionalEntityId(context, entry.OutputIdentity);
        WriteRange(context, entry.SourceRange);
        WriteRange(context, entry.OutputRange);
    }

    private static void WriteInstruction(CanonicalWriteContext context, SemanticInstruction instruction)
    {
        context.Writer.Write(instruction.SourceVirtualAddress.Value);
        context.Writer.Write(instruction.SourceFileOffset.Value);
        context.WriteString(instruction.Mnemonic);
        context.Writer.Write(instruction.Encoding);
        WriteRange(context, instruction.SourceRange);

        context.WriteCount(instruction.Operands.Count);
        foreach (var operand in instruction.Operands)
        {
            WriteOperand(context, operand);
            context.EnsureWithinCanonicalLimit();
        }

        var registerEffects = instruction.RegisterEffects
            .OrderBy(effect => GetRegisterSortKey(effect.Register), StringComparer.Ordinal)
            .ThenBy(effect => (int)effect.Kind)
            .ThenBy(effect => effect.IsImplicit)
            .ToArray();
        context.WriteCount(registerEffects.Length);
        foreach (var effect in registerEffects)
        {
            WriteRegisterEffect(context, effect);
            context.EnsureWithinCanonicalLimit();
        }

        context.Writer.Write((byte)instruction.FlagEffects);
        context.Writer.Write((byte)instruction.ControlFlow);
        WriteOptionalTarget(context, instruction.ControlFlowTarget);
        WriteOptionalExpression(context, instruction.PcRelativeExpression);
        WriteOptionalLiteral(context, instruction.LiteralReference);

        var relocations = instruction.Relocations
            .OrderBy(GetRelocationSortKey, StringComparer.Ordinal)
            .ToArray();
        context.WriteCount(relocations.Length);
        foreach (var relocation in relocations)
        {
            WriteRelocation(context, relocation);
            context.EnsureWithinCanonicalLimit();
        }

        var references = instruction.References
            .OrderBy(reference => GetReferenceSortKey(reference), StringComparer.Ordinal)
            .ToArray();
        context.WriteCount(references.Length);
        foreach (var reference in references)
        {
            WriteReference(context, reference);
            context.EnsureWithinCanonicalLimit();
        }

        context.Writer.Write(instruction.OpaquePreservation ? (byte)1 : (byte)0);
    }

    private static void WriteOperand(CanonicalWriteContext context, SemanticOperand operand)
    {
        context.WriteString(operand.Name);
        context.Writer.Write((byte)operand.Kind);
        context.Writer.Write((byte)operand.Direction);
        context.Writer.Write(operand.IsImplicit ? (byte)1 : (byte)0);
        context.WriteString(operand.Codec);
        context.WriteOptionalString(operand.TiedTo);
        WriteOptionalRegister(context, operand.Register);
        context.WriteCount(operand.Registers.Count);
        foreach (var register in operand.Registers)
        {
            WriteRegister(context, register);
            context.EnsureWithinCanonicalLimit();
        }

        WriteOptionalMemory(context, operand.Memory);
        WriteOptionalInt64(context, operand.Immediate);
        WriteOptionalUInt64(context, operand.Target);
        WriteRegisterConstraint(context, operand.RegisterConstraint);
        context.Writer.Write(operand.RegisterWidth);
        context.Writer.Write(operand.FieldWidth);
        context.Writer.Write(operand.ElementWidth);
        context.Writer.Write(operand.AllowsStackPointer ? (byte)1 : (byte)0);
        context.Writer.Write(operand.AllowsZeroRegister ? (byte)1 : (byte)0);
        context.Writer.Write(operand.IsPageRelative ? (byte)1 : (byte)0);
        context.WriteString(operand.SemanticDomain);
    }

    private static void WriteRegisterEffect(CanonicalWriteContext context, SemanticRegisterEffect effect)
    {
        WriteRegister(context, effect.Register);
        context.Writer.Write((byte)effect.Kind);
        context.Writer.Write(effect.IsImplicit ? (byte)1 : (byte)0);
    }

    private static void WriteRegister(CanonicalWriteContext context, Aarch64RegisterView register)
    {
        context.Writer.Write((byte)register.Class);
        context.Writer.Write(register.Index);
        context.Writer.Write(register.Width);
        context.Writer.Write((byte)register.Role);
    }

    private static void WriteRegisterConstraint(
        CanonicalWriteContext context,
        Aarch64RegisterConstraint constraint)
    {
        context.Writer.Write(constraint.MinimumIndex);
        context.Writer.Write(constraint.MaximumIndex);
        context.Writer.Write(constraint.Step);
        context.Writer.Write(constraint.AllowedMask);
    }

    private static void WriteOptionalRegister(
        CanonicalWriteContext context,
        Aarch64RegisterView? register)
    {
        context.Writer.Write(register.HasValue ? (byte)1 : (byte)0);
        if (register is { } value)
        {
            WriteRegister(context, value);
        }
    }

    private static void WriteOptionalMemory(
        CanonicalWriteContext context,
        Aarch64MemoryReference? memory)
    {
        context.Writer.Write(memory is not null ? (byte)1 : (byte)0);
        if (memory is not { } value)
        {
            return;
        }

        WriteRegister(context, value.Base);
        WriteOptionalRegister(context, value.Index);
        context.Writer.Write(value.Offset);
        context.WriteString(value.AddressingMode);
        WriteOptionalUInt32(context, value.IndexModifier);
        context.Writer.Write(value.AccessSize);
        context.WriteString(value.Ordering);
        context.Writer.Write(value.WritesBack ? (byte)1 : (byte)0);
        context.WriteOptionalString(value.IndexModifierKind);
        context.Writer.Write(value.IndexModifierAmount);
    }

    private static void WriteOptionalTarget(
        CanonicalWriteContext context,
        SemanticTarget? target)
    {
        context.Writer.Write(target is not null ? (byte)1 : (byte)0);
        if (target is not null)
        {
            WriteTarget(context, target);
        }
    }

    private static void WriteTarget(CanonicalWriteContext context, SemanticTarget target)
    {
        context.Writer.Write((byte)target.Resolution);
        WriteOptionalUInt64(context, target.SourceAddress?.Value);
        WriteOptionalEntityId(context, target.Identity);

        var identities = target.CandidateIdentities
            .OrderBy(identity => (int)identity.Kind)
            .ThenBy(identity => identity.Value, StringComparer.Ordinal)
            .ToArray();
        context.WriteCount(identities.Length);
        foreach (var identity in identities)
        {
            WriteEntityId(context, identity);
            context.EnsureWithinCanonicalLimit();
        }

        var addresses = target.CandidateAddresses.OrderBy(address => address.Value).ToArray();
        context.WriteCount(addresses.Length);
        foreach (var address in addresses)
        {
            context.Writer.Write(address.Value);
            context.EnsureWithinCanonicalLimit();
        }

        context.WriteOptionalString(target.RuntimeBinding);
        context.WriteOptionalString(target.Diagnostic);
    }

    private static void WriteOptionalExpression(
        CanonicalWriteContext context,
        PcRelativeExpression? expression)
    {
        context.Writer.Write(expression is not null ? (byte)1 : (byte)0);
        if (expression is null)
        {
            return;
        }

        context.Writer.Write((byte)expression.Kind);
        context.Writer.Write(expression.Place.Value);
        WriteTarget(context, expression.Target);
        context.Writer.Write(expression.Scale);
        context.Writer.Write(expression.IsPageRelative ? (byte)1 : (byte)0);
        context.Writer.Write(expression.Addend);
    }

    private static void WriteOptionalLiteral(
        CanonicalWriteContext context,
        LiteralReference? literal)
    {
        context.Writer.Write(literal is not null ? (byte)1 : (byte)0);
        if (literal is null)
        {
            return;
        }

        WriteTarget(context, literal.Target);
        context.Writer.Write(literal.AccessSize);
        context.Writer.Write(literal.IsLoad ? (byte)1 : (byte)0);
        WriteOptionalRange(context, literal.PoolRange);
    }

    private static void WriteRelocation(CanonicalWriteContext context, RelocationBinding relocation)
    {
        context.Writer.Write((byte)relocation.Kind);
        WriteTarget(context, relocation.Target);
        context.Writer.Write(relocation.Addend);
        context.Writer.Write(relocation.SymbolIndex);
        context.Writer.Write(relocation.IsPlt ? (byte)1 : (byte)0);
        context.WriteOptionalString(relocation.SymbolName);
        WriteOptionalUInt32(context, relocation.RelocationType);
        WriteOptionalUInt64(context, relocation.RawInfo);
        WriteOptionalUInt64(context, relocation.RelocationAddress?.Value);
        WriteOptionalUInt64(context, relocation.RelocationTableAddress?.Value);
    }

    private static void WriteReference(CanonicalWriteContext context, SemanticReference reference)
    {
        context.Writer.Write((byte)reference.Kind);
        WriteTarget(context, reference.Target);
        context.Writer.Write(reference.OperandIndex);
        WriteOptionalExpression(context, reference.PcRelative);
        WriteOptionalLiteral(context, reference.Literal);
        WriteOptionalRelocation(context, reference.Relocation);
        context.WriteOptionalString(reference.Description);
    }

    private static void WriteOptionalRelocation(
        CanonicalWriteContext context,
        RelocationBinding? relocation)
    {
        context.Writer.Write(relocation is not null ? (byte)1 : (byte)0);
        if (relocation is not null)
        {
            WriteRelocation(context, relocation);
        }
    }

    private static void WriteRange(CanonicalWriteContext context, SemanticSourceRange range)
    {
        context.Writer.Write(range.FileOffset.Value);
        context.Writer.Write(range.VirtualAddress.Value);
        context.Writer.Write(range.Size);
    }

    private static void WriteOptionalRange(
        CanonicalWriteContext context,
        SemanticSourceRange? range)
    {
        context.Writer.Write(range.HasValue ? (byte)1 : (byte)0);
        if (range is { } value)
        {
            WriteRange(context, value);
        }
    }

    private static void WriteEntityId(CanonicalWriteContext context, SemanticEntityId identity)
    {
        context.Writer.Write((byte)identity.Kind);
        context.WriteString(identity.Value);
    }

    private static void WriteOptionalEntityId(
        CanonicalWriteContext context,
        SemanticEntityId? identity)
    {
        context.Writer.Write(identity.HasValue ? (byte)1 : (byte)0);
        if (identity is { } value)
        {
            WriteEntityId(context, value);
        }
    }

    private static void WriteFixup(CanonicalWriteContext context, SemanticFixupSnapshot snapshot)
    {
        var fixup = snapshot.Fixup;
        context.Writer.Write((byte)snapshot.ResolutionState);
        context.Writer.Write((byte)fixup.Kind);
        context.Writer.Write(fixup.SourceAddress.Value);
        context.Writer.Write(fixup.SourceFileOffset.Value);
        context.Writer.Write(fixup.OriginalEncoding);
        WriteTarget(context, fixup.Target);
        WriteRange(context, fixup.SourceRange);
        WriteOptionalExpression(context, fixup.Expression);
        WriteOptionalRelocation(context, fixup.Relocation);
        context.Writer.Write((byte)fixup.Relaxation);
        var options = fixup.RelaxationOptions
            .Distinct()
            .OrderBy(option => (int)option)
            .ToArray();
        context.WriteCount(options.Length);
        foreach (var option in options)
        {
            context.Writer.Write((byte)option);
            context.EnsureWithinCanonicalLimit();
        }
    }

    private static void WriteExtension(
        CanonicalWriteContext context,
        ISemanticPlanExtension extension)
    {
        context.Writer.Write((byte)extension.Kind);
        switch (extension)
        {
            case SemanticIndirectTargetExtension indirect:
                WriteEntityId(context, indirect.SourceInstruction);
                context.Writer.Write(indirect.SourceAddress.Value);
                WriteTarget(context, indirect.Target);
                context.WriteString(indirect.Diagnostic);
                break;
            case SemanticUnresolvedReferenceExtension unresolved:
                WriteEntityId(context, unresolved.SourceInstruction);
                context.Writer.Write(unresolved.SourceAddress.Value);
                context.Writer.Write((byte)unresolved.ReferenceKind);
                WriteTarget(context, unresolved.Target);
                context.WriteString(unresolved.Diagnostic);
                break;
            case SemanticRelocationBindingExtension relocation:
                WriteEntityId(context, relocation.RelocationSite);
                WriteRelocation(context, relocation.Binding);
                context.WriteString(relocation.Diagnostic);
                break;
            case SemanticTlsBindingExtension tls:
                WriteTlsBinding(context, tls.Binding);
                context.WriteOptionalString(tls.Diagnostic);
                break;
            case SemanticJumpTableExtension jumpTable:
                WriteEntityId(context, jumpTable.TableIdentity);
                WriteRange(context, jumpTable.TableRange);
                context.Writer.Write(jumpTable.EntrySize);
                context.WriteOptionalString(jumpTable.Encoding);
                context.Writer.Write(jumpTable.BaseAddress.HasValue ? (byte)1 : (byte)0);
                if (jumpTable.BaseAddress is { } baseAddress)
                {
                    context.Writer.Write(baseAddress.Value);
                }

                context.Writer.Write(jumpTable.TargetBaseAddress.HasValue ? (byte)1 : (byte)0);
                if (jumpTable.TargetBaseAddress is { } targetBaseAddress)
                {
                    context.Writer.Write(targetBaseAddress.Value);
                }

                WriteOptionalEntityId(context, jumpTable.SourceInstruction);
                context.Writer.Write(jumpTable.IsSigned ? (byte)1 : (byte)0);
                context.Writer.Write(jumpTable.Scale);
                context.Writer.Write(jumpTable.Addend);
                context.Writer.Write(jumpTable.LowerBound);
                context.Writer.Write(jumpTable.UpperBound);
                WriteOptionalTarget(context, jumpTable.DefaultTarget);
                context.Writer.Write((byte)jumpTable.Ownership);
                context.Writer.Write((byte)jumpTable.RewritePolicy);
                WriteOptionalRange(context, jumpTable.OutputRange);
                context.WriteOptionalString(jumpTable.Diagnostic);

                var targets = jumpTable.Targets
                    .OrderBy(target => GetTargetSortKey(target), StringComparer.Ordinal)
                    .ToArray();
                context.WriteCount(targets.Length);
                foreach (var target in targets)
                {
                    WriteTarget(context, target);
                    context.EnsureWithinCanonicalLimit();
                }

                var entries = jumpTable.Entries
                    .OrderBy(entry => entry.Index)
                    .ThenBy(entry => entry.EntryIdentity.Value, StringComparer.Ordinal)
                    .ToArray();
                context.WriteCount(entries.Length);
                foreach (var entry in entries)
                {
                    WriteEntityId(context, entry.EntryIdentity);
                    context.Writer.Write(entry.Index);
                    context.Writer.Write(entry.EncodedValue);
                    WriteRange(context, entry.SourceRange);
                    WriteTarget(context, entry.Target);
                    context.EnsureWithinCanonicalLimit();
                }

                break;
            case SemanticCfiEffectExtension cfi:
                WriteEntityId(context, cfi.SourceIdentity);
                WriteRange(context, cfi.SourceRange);
                context.WriteString(cfi.Effect);
                var effects = cfi.RegisterEffects
                    .OrderBy(effect => GetRegisterSortKey(effect.Register), StringComparer.Ordinal)
                    .ThenBy(effect => (int)effect.Kind)
                    .ThenBy(effect => effect.IsImplicit)
                    .ToArray();
                context.WriteCount(effects.Length);
                foreach (var effect in effects)
                {
                    WriteRegisterEffect(context, effect);
                    context.EnsureWithinCanonicalLimit();
                }

                context.WriteOptionalString(cfi.Diagnostic);
                break;
            default:
                throw new SnapshotEncodingException(
                    "The semantic-plan extension has no canonical encoding.",
                    DiagnosticCode.SemanticPlanSnapshotUnsupported);
        }
    }

    private static void WriteTlsBinding(CanonicalWriteContext context, TlsBinding binding)
    {
        context.Writer.Write((byte)binding.AccessModel);
        context.Writer.Write((byte)binding.RelocationFamily);
        WriteEntityId(context, binding.SourceIdentity);
        WriteRange(context, binding.SourceRange);
        WriteRange(context, binding.InstructionSequence.SourceRange);
        context.Writer.Write((byte)binding.InstructionSequence.ResolverKind);
        WriteOptionalTarget(context, binding.InstructionSequence.ResolverTarget);
        context.WriteCount(binding.InstructionSequence.Instructions.Count);
        foreach (var instruction in binding.InstructionSequence.Instructions)
        {
            WriteRange(context, instruction.SourceRange);
            context.Writer.Write(instruction.Encoding);
            context.WriteString(instruction.Mnemonic);
            context.Writer.Write((byte)instruction.Role);
            WriteTlsRegisters(context, instruction.InputRegisters);
            WriteTlsRegisters(context, instruction.OutputRegisters);
            var effects = instruction.RegisterEffects
                .OrderBy(effect => GetRegisterSortKey(effect.Register), StringComparer.Ordinal)
                .ThenBy(effect => (int)effect.Kind)
                .ThenBy(effect => effect.IsImplicit)
                .ToArray();
            context.WriteCount(effects.Length);
            foreach (var effect in effects)
            {
                WriteRegisterEffect(context, effect);
                context.EnsureWithinCanonicalLimit();
            }

            context.Writer.Write(instruction.IsCall ? (byte)1 : (byte)0);
            context.Writer.Write(instruction.IsResolverCall ? (byte)1 : (byte)0);
            context.EnsureWithinCanonicalLimit();
        }

        WriteTlsModule(context, binding.Module);
        WriteOptionalTlsSymbol(context, binding.Symbol);
        context.Writer.Write(binding.Addend);
        var sites = binding.RelocationSites
            .OrderBy(site => site.PairOrdinal)
            .ThenBy(site => site.SourceRange.VirtualAddress.Value)
            .ThenBy(site => site.SourceRange.FileOffset.Value)
            .ThenBy(site => (int)site.Family)
            .ToArray();
        context.WriteCount(sites.Length);
        foreach (var site in sites)
        {
            context.Writer.Write((byte)site.Family);
            WriteRange(context, site.SourceRange);
            WriteRelocation(context, site.Binding);
            context.Writer.Write(site.PairOrdinal);
            context.Writer.Write(site.IsGotOrDescriptorOwned ? (byte)1 : (byte)0);
            context.EnsureWithinCanonicalLimit();
        }

        context.Writer.Write(binding.ResolverCall is not null ? (byte)1 : (byte)0);
        if (binding.ResolverCall is { } resolverCall)
        {
            WriteRange(context, resolverCall.SourceRange);
            WriteRelocation(context, resolverCall.Relocation);
        }

        context.Writer.Write(binding.ModuleOwner is not null ? (byte)1 : (byte)0);
        if (binding.ModuleOwner is { } moduleOwner)
        {
            WriteEntityId(context, moduleOwner.SourceIdentity);
            WriteRange(context, moduleOwner.SourceRange);
            WriteRelocation(context, moduleOwner.Relocation);
        }

        if (binding.AccessModel == TlsAccessModel.GeneralDynamic)
        {
            context.Writer.Write(binding.DtpRelOwner is not null ? (byte)1 : (byte)0);
            if (binding.DtpRelOwner is { } dtpRelOwner)
            {
                WriteEntityId(context, dtpRelOwner.SourceIdentity);
                WriteRange(context, dtpRelOwner.SourceRange);
                WriteRelocation(context, dtpRelOwner.Relocation);
            }
        }

        if (binding.AccessModel == TlsAccessModel.InitialExec)
        {
            context.Writer.Write(binding.GotEntry is not null ? (byte)1 : (byte)0);
            if (binding.GotEntry is { } gotEntry)
            {
                WriteTlsGotEntry(context, gotEntry);
            }
        }

        if (binding.AccessModel == TlsAccessModel.TlsDesc)
        {
            context.Writer.Write(binding.DescriptorOwner is not null ? (byte)1 : (byte)0);
            if (binding.DescriptorOwner is { } descriptorOwner)
            {
                WriteTlsDescriptorOwner(context, descriptorOwner);
            }
        }

        context.Writer.Write(binding.AccessSize);
        context.Writer.Write((byte)binding.AddressExpression.Kind);
        WriteTlsModule(context, binding.AddressExpression.Module);
        WriteOptionalTlsSymbol(context, binding.AddressExpression.Symbol);
        WriteOptionalRegister(context, binding.AddressExpression.BaseRegister);
        WriteOptionalRegister(context, binding.AddressExpression.ValueRegister);
        context.Writer.Write(binding.AddressExpression.Addend);
        var profiles = binding.ProfileRequirements.OrderBy(item => (int)item.Profile).ToArray();
        context.WriteCount(profiles.Length);
        foreach (var requirement in profiles)
        {
            context.Writer.Write((byte)requirement.Profile);
            context.Writer.Write(requirement.Required ? (byte)1 : (byte)0);
            context.EnsureWithinCanonicalLimit();
        }

        var runtimes = binding.RuntimeRequirements
            .OrderBy(item => (int)item.Runtime)
            .ThenBy(item => (int)item.Kind)
            .ToArray();
        context.WriteCount(runtimes.Length);
        foreach (var requirement in runtimes)
        {
            context.Writer.Write((byte)requirement.Runtime);
            context.Writer.Write((byte)requirement.Kind);
            context.Writer.Write(requirement.Required ? (byte)1 : (byte)0);
            context.EnsureWithinCanonicalLimit();
        }
    }

    private static void WriteTlsDescriptorOwner(
        CanonicalWriteContext context,
        TlsDescriptorOwnerBinding owner)
    {
        WriteEntityId(context, owner.SourceIdentity);
        WriteRange(context, owner.DescriptorRange);
        WriteRelocation(context, owner.Relocation);
        WriteOptionalTlsSymbol(context, owner.Symbol);
        context.Writer.Write(owner.Addend);
        context.Writer.Write(owner.DescriptorPlt.Value);
        context.Writer.Write(owner.DescriptorGot.Value);
        context.Writer.Write(owner.PltGot.Value);
        WriteRange(context, owner.ResolverPltRange);
        WriteRange(context, owner.ResolverGotRange);
    }

    private static void WriteTlsGotEntry(
        CanonicalWriteContext context,
        TlsGotEntryBinding gotEntry)
    {
        WriteEntityId(context, gotEntry.SourceIdentity);
        WriteRange(context, gotEntry.SourceRange);
        WriteRelocation(context, gotEntry.Relocation);
        WriteOptionalTlsSymbol(context, gotEntry.Symbol);
        context.Writer.Write(gotEntry.Addend);
    }


    private static void WriteTlsRegisters(
        CanonicalWriteContext context,
        IReadOnlyList<Aarch64RegisterView> registers)
    {
        var ordered = registers.OrderBy(GetRegisterSortKey, StringComparer.Ordinal).ToArray();
        context.WriteCount(ordered.Length);
        foreach (var register in ordered)
        {
            WriteRegister(context, register);
            context.EnsureWithinCanonicalLimit();
        }
    }

    private static void WriteTlsModule(CanonicalWriteContext context, TlsModuleIdentity module)
    {
        context.Writer.Write((byte)module.Kind);
        context.WriteString(module.Identity);
        context.WriteOptionalString(module.Soname);
        WriteOptionalUInt32(context, module.RuntimeModuleIndex);
        context.Writer.Write(module.Template is not null ? (byte)1 : (byte)0);
        if (module.Template is { } template)
        {
            WriteTlsTemplate(context, template);
        }
    }

    private static void WriteTlsTemplate(CanonicalWriteContext context, TlsTemplateContract template)
    {
        context.Writer.Write(template.FileOffset.Value);
        context.Writer.Write(template.VirtualAddress.Value);
        context.Writer.Write(template.FileSize);
        context.Writer.Write(template.MemorySize);
        context.Writer.Write(template.Alignment);
        context.Writer.Write(template.Permissions);
        context.Writer.Write(template.OwningLoadProgramHeaderIndex);
        context.WriteString(template.InitializedTemplateSha256);
    }

    private static void WriteOptionalTlsSymbol(CanonicalWriteContext context, TlsSymbolIdentity? symbol)
    {
        context.Writer.Write(symbol is not null ? (byte)1 : (byte)0);
        if (symbol is null)
        {
            return;
        }

        context.Writer.Write(symbol.SymbolIndex);
        context.WriteString(symbol.Name);
        context.Writer.Write(symbol.Binding);
        context.Writer.Write(symbol.SymbolType);
        context.Writer.Write(symbol.Visibility);
        context.Writer.Write(symbol.SectionIndex);
        context.Writer.Write(symbol.Value);
        context.Writer.Write(symbol.Size);
        context.Writer.Write(symbol.IsDefined ? (byte)1 : (byte)0);
    }

    private static void WriteDiagnostic(CanonicalWriteContext context, Diagnostic diagnostic)
    {
        context.Writer.Write((byte)diagnostic.Severity);
        context.Writer.Write((uint)diagnostic.Code);
        context.Writer.Write(diagnostic.Offset.HasValue ? (byte)1 : (byte)0);
        if (diagnostic.Offset is { } offset)
        {
            context.Writer.Write(offset);
        }

        context.WriteString(diagnostic.Message);
    }

    private static void WriteOptionalInt64(CanonicalWriteContext context, long? value)
    {
        context.Writer.Write(value.HasValue ? (byte)1 : (byte)0);
        if (value is { } actual)
        {
            context.Writer.Write(actual);
        }
    }

    private static void WriteOptionalUInt32(CanonicalWriteContext context, uint? value)
    {
        context.Writer.Write(value.HasValue ? (byte)1 : (byte)0);
        if (value is { } actual)
        {
            context.Writer.Write(actual);
        }
    }

    private static void WriteOptionalUInt64(CanonicalWriteContext context, ulong? value)
    {
        context.Writer.Write(value.HasValue ? (byte)1 : (byte)0);
        if (value is { } actual)
        {
            context.Writer.Write(actual);
        }
    }

    private static string GetRegisterSortKey(Aarch64RegisterView register) =>
        GetIntSortKey((int)register.Class)
        + GetByteSortKey(register.Index)
        + GetByteSortKey(register.Width)
        + GetIntSortKey((int)register.Role);

    private static string GetTargetSortKey(SemanticTarget target)
    {
        var candidateIdentities = target.CandidateIdentities
            .OrderBy(identity => GetEntitySortKey(identity), StringComparer.Ordinal)
            .Select(GetEntitySortKey)
            .ToArray();
        var candidateAddresses = target.CandidateAddresses
            .OrderBy(address => address.Value)
            .Select(address => GetUlongSortKey(address.Value))
            .ToArray();

        return GetIntSortKey((int)target.Resolution)
            + GetOptionalUInt64SortKey(target.SourceAddress?.Value)
            + GetOptionalEntitySortKey(target.Identity)
            + GetCollectionSortKey(candidateIdentities)
            + GetCollectionSortKey(candidateAddresses)
            + GetOptionalStringSortKey(target.RuntimeBinding)
            + GetOptionalStringSortKey(target.Diagnostic);
    }

    private static string GetRelocationSortKey(RelocationBinding relocation) =>
        GetIntSortKey((int)relocation.Kind)
        + GetTargetSortKey(relocation.Target)
        + GetLongSortKey(relocation.Addend)
        + GetUIntSortKey(relocation.SymbolIndex)
        + GetBoolSortKey(relocation.IsPlt)
        + GetOptionalStringSortKey(relocation.SymbolName)
        + GetOptionalUIntSortKey(relocation.RelocationType)
        + GetOptionalUInt64SortKey(relocation.RawInfo)
        + GetOptionalUInt64SortKey(relocation.RelocationAddress?.Value)
        + GetOptionalUInt64SortKey(relocation.RelocationTableAddress?.Value);

    private static string GetReferenceSortKey(SemanticReference reference) =>
        GetIntSortKey((int)reference.Kind)
        + GetIntSortKey(reference.OperandIndex)
        + GetTargetSortKey(reference.Target)
        + GetOptionalExpressionSortKey(reference.PcRelative)
        + GetOptionalLiteralSortKey(reference.Literal)
        + GetOptionalRelocationSortKey(reference.Relocation)
        + GetOptionalStringSortKey(reference.Description);

    private static string GetOptionalExpressionSortKey(PcRelativeExpression? expression) =>
        expression is { } value
            ? GetBoolSortKey(true)
                + GetIntSortKey((int)value.Kind)
                + GetUlongSortKey(value.Place.Value)
                + GetTargetSortKey(value.Target)
                + GetIntSortKey(value.Scale)
                + GetBoolSortKey(value.IsPageRelative)
                + GetLongSortKey(value.Addend)
            : GetBoolSortKey(false);

    private static string GetOptionalLiteralSortKey(LiteralReference? literal) =>
        literal is { } value
            ? GetBoolSortKey(true)
                + GetTargetSortKey(value.Target)
                + GetIntSortKey(value.AccessSize)
                + GetBoolSortKey(value.IsLoad)
                + GetOptionalRangeSortKey(value.PoolRange)
            : GetBoolSortKey(false);

    private static string GetOptionalRelocationSortKey(RelocationBinding? relocation) =>
        relocation is { } value
            ? GetBoolSortKey(true) + GetRelocationSortKey(value)
            : GetBoolSortKey(false);

    private static string GetRangeSortKey(SemanticSourceRange range) =>
        GetUlongSortKey(range.FileOffset.Value)
        + GetUlongSortKey(range.VirtualAddress.Value)
        + GetUlongSortKey(range.Size);

    private static string GetOptionalRangeSortKey(SemanticSourceRange? range) =>
        range is { } value
            ? GetBoolSortKey(true) + GetRangeSortKey(value)
            : GetBoolSortKey(false);

    private static string GetEntitySortKey(SemanticEntityId identity) =>
        GetIntSortKey((int)identity.Kind) + GetOptionalStringSortKey(identity.Value);

    private static string GetOptionalEntitySortKey(SemanticEntityId? identity) =>
        identity is { } value
            ? GetBoolSortKey(true) + GetEntitySortKey(value)
            : GetBoolSortKey(false);

    private static string GetCollectionSortKey(IEnumerable<string> values)
    {
        var materialized = values.ToArray();
        return GetIntSortKey(materialized.Length) + string.Concat(materialized);
    }

    private static string GetOptionalStringSortKey(string? value) =>
        value is null
            ? GetBoolSortKey(false)
            : GetBoolSortKey(true) + GetStringSortKey(value);

    private static string GetStringSortKey(string value) =>
        GetIntSortKey(value.Length) + value;

    private static string GetIntSortKey(int value) =>
        unchecked((uint)value).ToString("X8", CultureInfo.InvariantCulture);

    private static string GetUIntSortKey(uint value) =>
        value.ToString("X8", CultureInfo.InvariantCulture);

    private static string GetOptionalUIntSortKey(uint? value) =>
        value is { } actual
            ? GetBoolSortKey(true) + GetUIntSortKey(actual)
            : GetBoolSortKey(false);

    private static string GetOptionalUInt64SortKey(ulong? value) =>
        value is { } actual
            ? GetBoolSortKey(true) + GetUlongSortKey(actual)
            : GetBoolSortKey(false);

    private static string GetUlongSortKey(ulong value) =>
        value.ToString("X16", CultureInfo.InvariantCulture);

    private static string GetLongSortKey(long value) =>
        unchecked((ulong)value).ToString("X16", CultureInfo.InvariantCulture);

    private static string GetByteSortKey(byte value) =>
        value.ToString("X2", CultureInfo.InvariantCulture);

    private static string GetBoolSortKey(bool value) => value ? "1" : "0";

    private sealed class CanonicalWriteContext
    {
        public CanonicalWriteContext(BinaryWriter writer, DiagnosticBag diagnostics)
        {
            Writer = writer;
            Diagnostics = diagnostics;
        }

        public BinaryWriter Writer { get; }

        public DiagnosticBag Diagnostics { get; }

        public int MetadataBytes { get; private set; }

        public void EnsureWithinCanonicalLimit()
        {
            if (Writer.BaseStream.Length > SemanticPlanSnapshotLimits.MaximumCanonicalBytes - DigestSize)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot exceeds its bounded canonical byte length.",
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
            }
        }

        public void WriteString(string value)
        {
            ArgumentNullException.ThrowIfNull(value);
            byte[] bytes;
            try
            {
                bytes = StrictUtf8.GetBytes(value);
            }
            catch (EncoderFallbackException)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot contains invalid UTF-8 metadata.",
                    DiagnosticCode.SemanticPlanSnapshotMalformed);
            }

            if (bytes.Length > SemanticPlanSnapshotLimits.MaximumStringBytes)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot contains oversized string metadata.",
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
            }

            if (MetadataBytes > SemanticPlanSnapshotLimits.MaximumMetadataBytes - bytes.Length)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot metadata exceeds its bounded byte limit.",
                    DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
            }

            MetadataBytes += bytes.Length;
            Writer.Write(checked((uint)bytes.Length));
            Writer.Write(bytes);
        }

        public void WriteOptionalString(string? value)
        {
            Writer.Write(value is not null ? (byte)1 : (byte)0);
            if (value is not null)
            {
                WriteString(value);
            }
        }

        public void WriteCount(int count)
        {
            if (count < 0)
            {
                throw new SnapshotEncodingException(
                    "The semantic-plan snapshot contains a negative collection count.",
                    DiagnosticCode.SemanticPlanSnapshotMalformed);
            }

            Writer.Write(checked((uint)count));
        }
    }
}
