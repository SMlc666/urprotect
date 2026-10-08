using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.SemanticPlanning;

public sealed record TlsSequenceRecognitionResult(
    TlsBinding? Binding,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Binding is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Recognizes one linker-described AArch64 TLS access from exact relocation families
/// and a bounded, already-decoded instruction sequence. It does not infer a model
/// from PT_TLS presence or a runtime's acceptance of the image.
/// </summary>
public static class Aarch64TlsSequenceRecognizer
{
    private const int MaximumInstructions = SemanticPlanSnapshotLimits.MaximumTlsInstructions;
    private const int MaximumRelocationSites = SemanticPlanSnapshotLimits.MaximumTlsRelocationSites;
    private const uint ThreadPointerMrsMask = 0xFFFF_FFE0;
    private const uint ThreadPointerMrsEncoding = 0xD53B_D040;

    public static TlsSequenceRecognitionResult Recognize(
        IEnumerable<SemanticInstruction> instructions,
        IEnumerable<TlsRelocationSite> relocationSites,
        TlsModuleIdentity module,
        TlsSymbolIdentity? symbol,
        SemanticTarget? resolverTarget = null,
        TlsGotEntryBinding? gotEntry = null)
    {
        ArgumentNullException.ThrowIfNull(instructions);
        ArgumentNullException.ThrowIfNull(relocationSites);
        ArgumentNullException.ThrowIfNull(module);
        var diagnostics = new DiagnosticBag();
        var instructionArray = instructions.Take(MaximumInstructions + 1).ToArray();
        var sites = relocationSites.Take(MaximumRelocationSites + 1).ToArray();
        if (instructionArray.Any(item => item is null)
            || sites.Any(item => item is null || item.Binding is null))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "TLS sequence recognition received a null instruction or relocation site.");
            return Failure(diagnostics);
        }

        if (instructionArray.Length > MaximumInstructions || sites.Length > MaximumRelocationSites)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "TLS sequence recognition exceeded its bounded instruction or relocation-site limit.");
            return Failure(diagnostics);
        }

        instructionArray = instructionArray
            .OrderBy(item => item.SourceVirtualAddress.Value)
            .ToArray();
        sites = sites
            .OrderBy(item => item.PairOrdinal)
            .ThenBy(item => item.SourceRange.VirtualAddress.Value)
            .ToArray();
        if (instructionArray.Length == 0 || sites.Length == 0)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "TLS sequence recognition requires decoded instructions and at least one relocation site.");
            return Failure(diagnostics);
        }

        var modelCandidates = sites
            .Select(site => site.Binding.RelocationType is { } type
                ? TlsRelocationClassifier.GetAccessModel(type)
                : null)
            .Where(model => model.HasValue)
            .Select(model => model!.Value)
            .Distinct()
            .ToArray();
        if (modelCandidates.Length != 1)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                modelCandidates.Length == 0
                    ? "TLS relocation records do not identify one access model; runtime-assigned DTPMOD/TPREL records are not sufficient to guess it."
                    : "The TLS sequence mixes relocation families from different access models.",
                sites[0].SourceRange.FileOffset.Value);
            return Failure(diagnostics);
        }

        var model = modelCandidates[0];
        if (symbol is null
            || string.IsNullOrWhiteSpace(symbol.Name)
            || (model is TlsAccessModel.LocalExec or TlsAccessModel.InitialExec
                && (!symbol.IsDefined || symbol.SymbolType != ElfConstants.SttTls)))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                model is TlsAccessModel.LocalExec or TlsAccessModel.InitialExec
                    ? "The TLS sequence has no resolved, defined STT_TLS symbol identity."
                    : "The TLS sequence has no resolved symbol identity.",
                sites[0].SourceRange.FileOffset.Value);
            return Failure(diagnostics);
        }

        if (string.IsNullOrWhiteSpace(module.Identity)
            || (model is TlsAccessModel.LocalExec or TlsAccessModel.InitialExec
                && (module.Kind != TlsModuleIdentityKind.ImageLocal
                    || module.RuntimeModuleIndex is not null
                    || module.Template is null)))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                model is TlsAccessModel.LocalExec or TlsAccessModel.InitialExec
                    ? "The TLS sequence has no resolved image-local module identity."
                    : "The TLS sequence has no resolved module identity.",
                sites[0].SourceRange.FileOffset.Value);
            return Failure(diagnostics);
        }

        if (instructionArray
                .Select((instruction, index) => (instruction, index))
                .Any(item =>
                    !item.instruction.SourceRange.IsInstructionRange
                    || item.instruction.SourceRange.VirtualAddress != item.instruction.SourceVirtualAddress
                    || item.instruction.SourceRange.FileOffset != item.instruction.SourceFileOffset)
            || instructionArray.Where((instruction, index) => index != 0
                && (!TryAdd(instructionArray[index - 1].SourceVirtualAddress.Value, sizeof(uint), out var nextAddress)
                    || instruction.SourceVirtualAddress.Value != nextAddress
                    || !TryAdd(instructionArray[index - 1].SourceFileOffset.Value, sizeof(uint), out var nextFileOffset)
                    || instruction.SourceFileOffset.Value != nextFileOffset))
            .Any())
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "A TLS instruction sequence contains a gap, overlap, or non-contiguous file mapping.",
                instructionArray[0].SourceFileOffset.Value);
            return Failure(diagnostics);
        }

        var instructionsByAddress = instructionArray.ToDictionary(item => item.SourceVirtualAddress);
        foreach (var site in sites)
        {
            var relocationType = site.Binding.RelocationType;
            var writeSize = relocationType is { } typedRelocation
                ? TlsRelocationClassifier.GetWriteSize(typedRelocation)
                : 0;
            if (relocationType is not { } type
                || writeSize == 0
                || site.SourceRange.Size != writeSize
                || site.SourceRange.FileOffset.Value % writeSize != 0
                || site.SourceRange.VirtualAddress.Value % writeSize != 0
                || !site.SourceRange.TryGetFileEnd(out _)
                || !site.SourceRange.TryGetVirtualEnd(out _)
                || !TlsRelocationClassifier.IsTlsRelocation(type)
                || TlsRelocationClassifier.GetFamily(type) != site.Family
                || !TlsRelocationClassifier.IsModelCompatible(model, site.Family)
                || site.Binding.RelocationAddress != site.SourceRange.VirtualAddress
                || !site.Binding.IsKindConsistent)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "A TLS relocation family does not match its raw relocation metadata or inferred access model.",
                    site.SourceRange.FileOffset.Value);
                continue;
            }

            if (site.Binding.SymbolName is { } relocationSymbol
                && !string.Equals(relocationSymbol, symbol.Name, StringComparison.Ordinal))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A TLS relocation symbol identity conflicts with the resolved sequence symbol.",
                    site.SourceRange.FileOffset.Value);
            }

            if (site.Binding.SymbolIndex != symbol.SymbolIndex
                || !string.Equals(site.Binding.SymbolName, symbol.Name, StringComparison.Ordinal))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "A TLS relocation symbol identity conflicts with the resolved sequence symbol.",
                    site.SourceRange.FileOffset.Value);
            }

            if (type < ElfConstants.RArm64TlsDtpMod64
                && !instructionsByAddress.ContainsKey(site.SourceRange.VirtualAddress))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "An instruction TLS relocation site is absent from the decoded source sequence.",
                    site.SourceRange.FileOffset.Value);
            }

            if (model == TlsAccessModel.LocalExec
                && (!instructionsByAddress.TryGetValue(site.SourceRange.VirtualAddress, out var tlsInstruction)
                    || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(type, tlsInstruction.Encoding)))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "A local-exec TPREL relocation must own an instruction with the exact supported opcode and immediate shift.",
                    site.SourceRange.FileOffset.Value);
            }
        }

        if (model == TlsAccessModel.InitialExec
            && (gotEntry is null
                || symbol is null
                || !ValidateGotEntry(gotEntry, module, symbol, sites[0].Binding.Addend, diagnostics)))
        {
            if (gotEntry is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsBindingUnresolved,
                    "The initial-exec TLSIE sequence has no uniquely owned source GOT entry.",
                    sites[0].SourceRange.FileOffset.Value);
            }
            return Failure(diagnostics);
        }

        if (diagnostics.HasErrors)
        {
            return Failure(diagnostics);
        }

        if (!ValidateRelocationPattern(model, instructionArray, sites, symbol, gotEntry, diagnostics))
        {
            return Failure(diagnostics);
        }

        var resolverKind = GetResolverKind(model);
        if (resolverKind != TlsResolverKind.None && !IsResolvedResolverTarget(model, resolverTarget))
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                model == TlsAccessModel.TlsDesc
                    ? "The TLSDESC resolver ownership is unresolved."
                    : "The __tls_get_addr call target is unresolved or belongs to another symbol.",
                instructionArray[0].SourceFileOffset.Value);
            return Failure(diagnostics);
        }

        if (!ValidateInstructionPattern(model, instructionArray, sites, resolverKind, diagnostics))
        {
            return Failure(diagnostics);
        }

        var accessInstruction = FindTlsMemoryAccess(instructionArray, resolverKind);
        if (accessInstruction is null || !TryGetAccessSize(accessInstruction, out var accessSize))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS sequence has no resolved final memory access width.",
                instructionArray[^1].SourceFileOffset.Value);
            return Failure(diagnostics);
        }

        var sequenceRange = new SemanticSourceRange(
            instructionArray[0].SourceFileOffset,
            instructionArray[0].SourceVirtualAddress,
            checked((ulong)instructionArray.Length * sizeof(uint)));
        if (!sequenceRange.TryGetFileEnd(out _) || !sequenceRange.TryGetVirtualEnd(out _))
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS source sequence range overflows its file or virtual address domain.",
                sequenceRange.FileOffset.Value);
            return Failure(diagnostics);
        }

        var instructionRecords = instructionArray.Select((instruction, index) =>
        {
            var isResolverCall = resolverKind != TlsResolverKind.None
                && IsResolverInstruction(model, instruction);
            var role = GetRole(model, instruction, index, instructionArray, isResolverCall, accessInstruction);
            return new TlsInstructionRecord(
                instruction.SourceRange,
                instruction.Encoding,
                instruction.Mnemonic,
                role,
                GetRegisters(instruction, Aarch64OperandDirection.Input),
                GetRegisters(instruction, Aarch64OperandDirection.Output),
                instruction.RegisterEffects,
                IsCallInstruction(instruction),
                isResolverCall);
        }).ToArray();

        var mrsInstruction = instructionArray.FirstOrDefault(IsThreadPointerMrs);
        Aarch64RegisterView? threadPointerRegister = null;
        if (mrsInstruction is not null)
        {
            var threadPointerRegisters = GetRegisters(mrsInstruction, Aarch64OperandDirection.Output);
            if (threadPointerRegisters.Length > 0)
            {
                threadPointerRegister = threadPointerRegisters[0];
            }
        }
        var accessBaseRegister = accessInstruction!.Operands
            .Select(operand => operand.Memory?.Base)
            .FirstOrDefault(register => register.HasValue);
        var accessOutputRegisters = GetRegisters(accessInstruction, Aarch64OperandDirection.Output);
        Aarch64RegisterView? accessValueRegister = accessOutputRegisters.Length == 0
            ? null
            : accessOutputRegisters[0];
        var addressKind = model switch
        {
            TlsAccessModel.LocalExec or TlsAccessModel.InitialExec => TlsAddressExpressionKind.ThreadPointerRelative,
            TlsAccessModel.LocalDynamic => TlsAddressExpressionKind.ModuleRelative,
            TlsAccessModel.GeneralDynamic => TlsAddressExpressionKind.ResolverReturned,
            TlsAccessModel.TlsDesc => TlsAddressExpressionKind.DescriptorMediated,
            _ => throw new ArgumentException("An unsupported TLS access model reached semantic projection.", nameof(instructions)),
        };
        var primaryFamily = model switch
        {
            TlsAccessModel.LocalExec => TlsRelocationFamily.Tprel,
            TlsAccessModel.InitialExec => TlsRelocationFamily.GotTprel,
            TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic => TlsRelocationFamily.Dtpmod,
            TlsAccessModel.TlsDesc => TlsRelocationFamily.TlsDesc,
            _ => throw new ArgumentException("An unsupported TLS access model reached semantic projection.", nameof(instructions)),
        };
        var profileRequirements = new[]
        {
            new TlsProfileRequirement(TlsProfile.OuterExecveat, Required: true),
            new TlsProfileRequirement(TlsProfile.HostContextEntry, Required: true),
        };
        var runtimeRequirements = CreateRuntimeRequirements(model);
        var binding = new TlsBinding(
            model,
            primaryFamily,
            SemanticEntityId.RelocationSite(
                $"tls:{model}:{instructionArray[0].SourceVirtualAddress.Value:X}"),
            sequenceRange,
            new TlsInstructionSequence(sequenceRange, instructionRecords, resolverKind, resolverTarget),
            module,
            symbol,
            sites[0].Binding.Addend,
            sites,
            accessSize,
            new TlsAddressExpression(
                addressKind,
                module,
                symbol,
                model is TlsAccessModel.LocalExec or TlsAccessModel.InitialExec
                    ? threadPointerRegister
                    : accessBaseRegister,
                accessValueRegister,
                sites[0].Binding.Addend),
            profileRequirements,
            runtimeRequirements,
            gotEntry);
        return new TlsSequenceRecognitionResult(binding, diagnostics.ToArray());
    }

    private static bool ValidateGotEntry(
        TlsGotEntryBinding gotEntry,
        TlsModuleIdentity module,
        TlsSymbolIdentity symbol,
        long addend,
        DiagnosticBag diagnostics)
    {
        var relocation = gotEntry.Relocation;
        var expectedTarget = $"tls-got:{module.Identity}:{symbol.Name}";
        var valid = gotEntry.SourceRange.Size == sizeof(ulong)
            && gotEntry.SourceRange.FileOffset.Value % sizeof(ulong) == 0
            && gotEntry.SourceRange.VirtualAddress.Value % sizeof(ulong) == 0
            && gotEntry.Symbol == symbol
            && gotEntry.Addend == addend
            && gotEntry.SourceIdentity.Value.Length > 0
            && relocation.RelocationType == ElfConstants.RArm64TlsTprel64
            && !relocation.IsPlt
            && relocation.Kind == Aarch64RelocationKind.ThreadLocal
            && relocation.SymbolIndex == symbol.SymbolIndex
            && string.Equals(relocation.SymbolName, symbol.Name, StringComparison.Ordinal)
            && relocation.Addend == addend
            && relocation.RelocationAddress == gotEntry.SourceRange.VirtualAddress
            && relocation.Target.Resolution == SemanticTargetResolution.RuntimeResolved
            && string.Equals(relocation.Target.RuntimeBinding, expectedTarget, StringComparison.Ordinal)
            && relocation.IsKindConsistent;
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsBindingUnresolved,
                "The TLSIE GOT entry ownership does not match the image-local module, symbol, relocation type, range, or addend.",
                gotEntry.SourceRange.FileOffset.Value);
        }

        return valid;
    }

    private static bool ValidateRelocationPattern(
        TlsAccessModel model,
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> sites,
        TlsSymbolIdentity? symbol,
        TlsGotEntryBinding? gotEntry,
        DiagnosticBag diagnostics)
    {
        var complete = TlsRelocationClassifier.IsCompleteRelocationPattern(
            model,
            sites.Where(site => site.Binding.RelocationType.HasValue)
                .Select(site => site.Binding.RelocationType!.Value));
        if (!complete)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The TLS relocation family is incomplete or is inconsistent with the inferred access model.",
                sites[0].SourceRange.FileOffset.Value);
        }

        if (model == TlsAccessModel.InitialExec)
        {
            var validPair = sites.Count == 1
                && sites[0].PairOrdinal == 0
                && gotEntry is not null
                && sites[0].Binding.RelocationType == ElfConstants.RArm64TlsIeLdGottprelPrel19
                && Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19Pair(instructions, sites);
            if (!validPair)
            {
                validPair = sites.Count == 2
                    && sites[0].PairOrdinal == 0
                    && sites[1].PairOrdinal == 1
                    && gotEntry is not null
                    && ((sites[0].Binding.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG1
                            && sites[1].Binding.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG0Nc
                            && Aarch64TlsInstructionSemantics.IsSupportedInitialExecMovwPair(instructions, sites))
                        || (sites[0].Binding.RelocationType == ElfConstants.RArm64TlsIeAdrGottprelPage21
                            && sites[1].Binding.RelocationType == ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
                            && Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64Pair(instructions, sites)));
            }
            if (!validPair)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "The supported initial-exec rewrite requires the standalone TLSIE LD_GOTTPREL_PREL19 chain or an exact ordered TLSIE MOVW G1/G0_NC or ADRP/LD64 GOTTPREL pair and TP/GOT address chain.",
                    sites[0].SourceRange.FileOffset.Value);
                complete = false;
            }
        }
        else if (model == TlsAccessModel.LocalExec)
        {
            var firstType = sites[0].Binding.RelocationType.GetValueOrDefault();
            var secondType = sites.Count > 1 ? sites[1].Binding.RelocationType.GetValueOrDefault() : 0;
            var addPair = firstType == ElfConstants.RArm64TlsLeAddTprelHi12
                && secondType is ElfConstants.RArm64TlsLeAddTprelLo12 or ElfConstants.RArm64TlsLeAddTprelLo12Nc;
            var movwPair = firstType == ElfConstants.RArm64TlsLeMovwTprelG1
                && secondType == ElfConstants.RArm64TlsLeMovwTprelG0Nc;
            var ldst32Pair = firstType == ElfConstants.RArm64TlsLeAddTprelHi12
                && secondType == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc;
            var validPair = sites.Count == 2
                && sites[0].PairOrdinal == 0
                && sites[1].PairOrdinal == 1
                && (addPair || movwPair || ldst32Pair)
                && sites[0].SourceRange.VirtualAddress.Value < sites[1].SourceRange.VirtualAddress.Value
                && sites[0].SourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && sites[1].SourceRange.FileOffset.Value
                    == sites[0].SourceRange.FileOffset.Value + sizeof(uint)
                && sites[0].Binding.Addend == sites[1].Binding.Addend;
            if (validPair && addPair)
            {
                validPair = Aarch64TlsInstructionSemantics.IsSupportedLocalExecAddPair(instructions, sites);
            }
            if (validPair && movwPair)
            {
                var instructionMap = instructions.ToDictionary(item => item.SourceVirtualAddress);
                validPair = instructionMap.TryGetValue(sites[0].SourceRange.VirtualAddress, out var firstInstruction)
                    && instructionMap.TryGetValue(sites[1].SourceRange.VirtualAddress, out var secondInstruction)
                    && Aarch64TlsInstructionSemantics.IsSupportedLocalExecMovwPair(
                        firstType,
                        firstInstruction.Encoding,
                        sites[0].SourceRange.VirtualAddress.Value,
                        sites[0].Binding.Addend,
                        secondType,
                        secondInstruction.Encoding,
                        sites[1].SourceRange.VirtualAddress.Value,
                        sites[1].Binding.Addend);
            }
            if (validPair && ldst32Pair)
            {
                validPair = symbol is not null
                    && Aarch64TlsInstructionSemantics.TryAddSigned(
                        symbol.Value,
                        sites[0].Binding.Addend,
                        out var tprelOffset)
                    && Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                        instructions,
                        sites,
                        tprelOffset);
                if (!validPair)
                {
                    diagnostics.Error(
                        DiagnosticCode.TlsSequenceMalformed,
                        "The TLSLE LDST32 relocation requires a representable 32-bit-aligned TP-relative offset and matching ADD/unsigned-immediate fields.",
                        sites[0].SourceRange.FileOffset.Value);
                }
            }

            if (!validPair)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsSequenceMalformed,
                    "The supported local-exec rewrite requires one ordered ADD HI12/LO12, ADD HI12/LDST32 LO12_NC, or MOVW G1/G0_NC pair with consistent addends and matching instruction forms.",
                    sites[0].SourceRange.FileOffset.Value);
                complete = false;
            }
        }

        return complete;
    }

    private static bool ValidateInstructionPattern(
        TlsAccessModel model,
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        TlsResolverKind resolverKind,
        DiagnosticBag diagnostics)
    {
        var hasThreadPointer = instructions.Any(IsThreadPointerMrs);
        var adrpIndex = FindMnemonic(instructions, "adrp");
        var addIndex = FindMnemonic(instructions, "add");
        var memoryIndices = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => IsMemoryInstruction(item.instruction))
            .Select(item => item.index)
            .ToArray();
        var resolverIndex = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => IsResolverInstruction(model, item.instruction))
            .Select(item => item.index)
            .ToArray();
        var valid = model switch
        {
            TlsAccessModel.LocalExec => hasThreadPointer
                && addIndex >= 0
                && memoryIndices.Length > 0
                && (relocationSites[0].Binding.RelocationType != ElfConstants.RArm64TlsLeMovwTprelG1
                    || IsSupportedLocalExecMovwSequence(instructions, relocationSites, memoryIndices)),
            TlsAccessModel.InitialExec => relocationSites[0].Binding.RelocationType == ElfConstants.RArm64TlsIeLdGottprelPrel19
                ? Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19Pair(
                    instructions,
                    relocationSites)
                : relocationSites[0].Binding.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG1
                    ? Aarch64TlsInstructionSemantics.IsSupportedInitialExecMovwPair(
                        instructions,
                        relocationSites)
                    : Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64Pair(
                        instructions,
                        relocationSites),
            TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic => adrpIndex >= 0
                && addIndex > adrpIndex
                && resolverKind == TlsResolverKind.TlsGetAddr
                && resolverIndex.Length == 1
                && resolverIndex[0] > addIndex
                && memoryIndices.Any(index => index > resolverIndex[0]),
            TlsAccessModel.TlsDesc => adrpIndex >= 0
                && FindMnemonic(instructions, "ldr") > adrpIndex
                && addIndex > adrpIndex
                && resolverKind == TlsResolverKind.TlsDesc
                && resolverIndex.Length == 1
                && resolverIndex[0] > addIndex
                && instructions.Skip(resolverIndex[0] + 1).Any(instruction =>
                    string.Equals(instruction.Mnemonic, "add", StringComparison.OrdinalIgnoreCase))
                && memoryIndices.Any(index => index > resolverIndex[0]),
            _ => false,
        };
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsSequenceMalformed,
                "The decoded AArch64 TLS instruction sequence is incomplete or inconsistent with its relocation model.",
                instructions[0].SourceFileOffset.Value);
        }

        return valid;
    }

    private static TlsRuntimeRequirement[] CreateRuntimeRequirements(TlsAccessModel model)
    {
        var requirements = model switch
        {
            TlsAccessModel.LocalExec => new[]
            {
                (TlsRuntimeRequirementKind.StaticTlsSlot, true),
                (TlsRuntimeRequirementKind.ThreadPointerRelativeAccess, true),
            },
            TlsAccessModel.InitialExec => new[]
            {
                (TlsRuntimeRequirementKind.LoaderAllocatedTlsModule, true),
                (TlsRuntimeRequirementKind.StaticTlsSlot, true),
                (TlsRuntimeRequirementKind.ThreadPointerRelativeAccess, true),
            },
            TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic => new[]
            {
                (TlsRuntimeRequirementKind.LoaderAllocatedTlsModule, true),
                (TlsRuntimeRequirementKind.TlsGetAddrResolver, true),
            },
            TlsAccessModel.TlsDesc => new[]
            {
                (TlsRuntimeRequirementKind.LoaderAllocatedTlsModule, true),
                (TlsRuntimeRequirementKind.TlsDescResolver, true),
            },
            _ => throw new ArgumentOutOfRangeException(nameof(model)),
        };
        return Enum.GetValues<TlsRuntime>()
            .Where(runtime => runtime != TlsRuntime.Aarch64SystemLoader)
            .SelectMany(runtime => requirements
                .Select(requirement => new TlsRuntimeRequirement(runtime, requirement.Item1, requirement.Item2))
                .Append(new TlsRuntimeRequirement(
                    runtime,
                    TlsRuntimeRequirementKind.CurrentThreadLifecycle,
                    true))
                .Append(new TlsRuntimeRequirement(
                    runtime,
                    TlsRuntimeRequirementKind.RegisteredWorkerLifecycle,
                    false)))
            .ToArray();
    }

    private static TlsInstructionRole GetRole(
        TlsAccessModel model,
        SemanticInstruction instruction,
        int index,
        IReadOnlyList<SemanticInstruction> instructions,
        bool isResolverCall,
        SemanticInstruction memoryAccess)
    {
        if (IsThreadPointerMrs(instruction))
        {
            return TlsInstructionRole.ThreadPointerRead;
        }

        if (isResolverCall)
        {
            return model == TlsAccessModel.TlsDesc
                ? TlsInstructionRole.DescriptorCall
                : TlsInstructionRole.ResolverCall;
        }

        if (ReferenceEquals(instruction, memoryAccess))
        {
            return TlsInstructionRole.TlsMemoryAccess;
        }

        var mnemonic = instruction.Mnemonic;
        if (model == TlsAccessModel.TlsDesc)
        {
            if (string.Equals(mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
                && !ReferenceEquals(instruction, memoryAccess))
            {
                return TlsInstructionRole.DescriptorLoad;
            }

            var resolverIndex = instructions.ToList().FindIndex(candidate => IsResolverInstruction(model, candidate));
            if (string.Equals(mnemonic, "add", StringComparison.OrdinalIgnoreCase)
                && resolverIndex >= 0
                && index > resolverIndex)
            {
                return TlsInstructionRole.AddressFinalization;
            }
        }

        if (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
            && index == 0)
        {
            return TlsInstructionRole.ModuleLookup;
        }

        if (string.Equals(mnemonic, "adrp", StringComparison.OrdinalIgnoreCase))
        {
            return TlsInstructionRole.AddressFormation;
        }

        if (string.Equals(mnemonic, "add", StringComparison.OrdinalIgnoreCase))
        {
            return model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                && index < instructions.ToList().FindIndex(candidate => IsResolverInstruction(model, candidate))
                ? TlsInstructionRole.SymbolOffsetFormation
                : TlsInstructionRole.AddressFormation;
        }

        if (model == TlsAccessModel.InitialExec
            && (instruction.Encoding & 0xFF00_0000u) == 0x5800_0000u
            && !ReferenceEquals(instruction, memoryAccess))
        {
            return TlsInstructionRole.GotEntryLoad;
        }

        if (model == TlsAccessModel.InitialExec
            && string.Equals(mnemonic, "ldr", StringComparison.OrdinalIgnoreCase)
            && !ReferenceEquals(instruction, memoryAccess))
        {
            return TlsInstructionRole.GotEntryLoad;
        }

        return TlsInstructionRole.SequencePreservation;
    }

    private static SemanticInstruction? FindTlsMemoryAccess(
        IReadOnlyList<SemanticInstruction> instructions,
        TlsResolverKind resolverKind)
    {
        var candidates = instructions.Where(IsMemoryInstruction).ToArray();
        if (resolverKind != TlsResolverKind.None)
        {
            // Resolver metadata loads are part of the call sequence. The final memory
            // operand after the resolver is the TLS object's access.
            var resolverIndex = Array.FindIndex(instructions.ToArray(), instruction =>
                string.Equals(instruction.Mnemonic, "bl", StringComparison.OrdinalIgnoreCase)
                || string.Equals(instruction.Mnemonic, "blr", StringComparison.OrdinalIgnoreCase));
            if (resolverIndex >= 0)
            {
                candidates = instructions.Skip(resolverIndex + 1).Where(IsMemoryInstruction).ToArray();
            }
        }

        return candidates.LastOrDefault();
    }

    private static bool TryGetAccessSize(SemanticInstruction instruction, out int accessSize)
    {
        var memory = instruction.Operands.Select(operand => operand.Memory).FirstOrDefault(value => value is not null);
        if (memory is { AccessSize: > 0 } memoryReference)
        {
            accessSize = memoryReference.AccessSize;
            return accessSize is 1 or 2 or 4 or 8 or 16;
        }

        var mnemonic = instruction.Mnemonic.ToLowerInvariant();
        accessSize = mnemonic.StartsWith("ldrb", StringComparison.Ordinal)
            || mnemonic.StartsWith("strb", StringComparison.Ordinal)
            ? 1
            : mnemonic.StartsWith("ldrh", StringComparison.Ordinal)
                || mnemonic.StartsWith("strh", StringComparison.Ordinal)
                ? 2
                : instruction.Operands
                    .Where(operand => operand.Direction is Aarch64OperandDirection.Output or Aarch64OperandDirection.InputOutput)
                    .Select(operand => operand.Register?.Width)
                    .FirstOrDefault(width => width.HasValue) switch
                {
                    8 or 16 => 1,
                    32 => 4,
                    64 => 8,
                    _ => 0,
                };
        return accessSize is 1 or 2 or 4 or 8 or 16;
    }

    private static Aarch64RegisterView[] GetRegisters(
        SemanticInstruction instruction,
        Aarch64OperandDirection direction) => instruction.Operands
        .Where(operand => operand.Direction == direction
            || (direction == Aarch64OperandDirection.Input
                && operand.Direction == Aarch64OperandDirection.InputOutput)
            || (direction == Aarch64OperandDirection.Output
                && operand.Direction == Aarch64OperandDirection.InputOutput))
        .SelectMany(operand =>
        {
            var registers = new List<Aarch64RegisterView>();
            if (operand.Register is { } register)
            {
                registers.Add(register);
            }

            registers.AddRange(operand.Registers);
            if (operand.Memory is { } memory)
            {
                registers.Add(memory.Base);
                if (memory.Index is { } index)
                {
                    registers.Add(index);
                }
            }

            return registers;
        })
        .Distinct()
        .ToArray();

    private static bool IsThreadPointerMrs(SemanticInstruction instruction) =>
        string.Equals(instruction.Mnemonic, "mrs", StringComparison.OrdinalIgnoreCase)
        && (instruction.Encoding & ThreadPointerMrsMask) == ThreadPointerMrsEncoding;

    private static bool IsSupportedLocalExecMovwSequence(
        IReadOnlyList<SemanticInstruction> instructions,
        IReadOnlyList<TlsRelocationSite> relocationSites,
        IReadOnlyList<int> memoryIndices)
    {
        if (relocationSites.Count != 2 || memoryIndices.Count != 1)
        {
            return false;
        }

        var firstPairIndex = Array.FindIndex(instructions.ToArray(), instruction =>
            instruction.SourceVirtualAddress == relocationSites[0].SourceRange.VirtualAddress);
        var secondPairIndex = Array.FindIndex(instructions.ToArray(), instruction =>
            instruction.SourceVirtualAddress == relocationSites[1].SourceRange.VirtualAddress);
        if (firstPairIndex < 0
            || secondPairIndex != firstPairIndex + 1
            || !Aarch64TlsInstructionSemantics.TryGetLocalExecMovwRegister(
                relocationSites[0].Binding.RelocationType.GetValueOrDefault(),
                instructions[firstPairIndex].Encoding,
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
        if (threadPointerIndex != firstPairIndex - 1
            && threadPointerIndex != secondPairIndex + 1)
        {
            return false;
        }

        // The TP read and the MOVW pair must remain live at the same time. An
        // alias would make either the pair overwrite TP or the MRS overwrite
        // the TPREL value before ADD consumes both operands.
        if (threadPointerRegister == tprelRegister)
        {
            return false;
        }

        var expectedAddIndex = Math.Max(secondPairIndex, threadPointerIndex) + 1;
        var addInstructions = instructions
            .Select((instruction, index) => (instruction, index))
            .Where(item => item.index == expectedAddIndex
                && Aarch64TlsInstructionSemantics.TryGetLocalExecAddressRegister(
                    item.instruction.Encoding,
                    threadPointerRegister,
                    tprelRegister,
                    out _))
            .ToArray();
        if (addInstructions.Length != 1)
        {
            return false;
        }

        var addIndex = addInstructions[0].index;
        if (!Aarch64TlsInstructionSemantics.TryGetLocalExecAddressRegister(
                addInstructions[0].instruction.Encoding,
                threadPointerRegister,
                tprelRegister,
                out var addressRegister)
            || memoryIndices[0] != addIndex + 1)
        {
            return false;
        }

        var memoryBase = instructions[memoryIndices[0]].Operands
            .Select(operand => operand.Memory?.Base)
            .FirstOrDefault(register => register.HasValue);
        return memoryBase is { } baseRegister
            && baseRegister.Class == Aarch64RegisterClass.General
            && baseRegister.Role == Aarch64RegisterRole.None
            && baseRegister.Width == 64
            && baseRegister.Index == addressRegister;
    }

    private static bool IsMemoryInstruction(SemanticInstruction instruction) =>
        instruction.Operands.Any(operand => operand.Memory is not null)
        || instruction.Mnemonic.StartsWith("ldr", StringComparison.OrdinalIgnoreCase)
        || instruction.Mnemonic.StartsWith("str", StringComparison.OrdinalIgnoreCase);

    private static bool IsCallInstruction(SemanticInstruction instruction) =>
        instruction.ControlFlow == Aarch64ControlFlowKind.DirectCall
        || string.Equals(instruction.Mnemonic, "bl", StringComparison.OrdinalIgnoreCase)
        || string.Equals(instruction.Mnemonic, "blr", StringComparison.OrdinalIgnoreCase);

    private static bool IsResolverInstruction(TlsAccessModel model, SemanticInstruction instruction) =>
        model == TlsAccessModel.TlsDesc
            ? string.Equals(instruction.Mnemonic, "blr", StringComparison.OrdinalIgnoreCase)
                || instruction.ControlFlow == Aarch64ControlFlowKind.DirectCall
            : string.Equals(instruction.Mnemonic, "bl", StringComparison.OrdinalIgnoreCase)
                || instruction.ControlFlow == Aarch64ControlFlowKind.DirectCall;

    private static bool IsResolvedResolverTarget(TlsAccessModel model, SemanticTarget? target)
    {
        if (target is null || target.Resolution is SemanticTargetResolution.Unresolved or SemanticTargetResolution.BoundedSet)
        {
            return false;
        }

        var value = target.RuntimeBinding ?? target.Identity?.Value;
        return model == TlsAccessModel.TlsDesc
            ? string.Equals(value, "tlsdesc:resolver", StringComparison.Ordinal)
            : string.Equals(value, "symbol:__tls_get_addr", StringComparison.Ordinal)
                || string.Equals(value, "__tls_get_addr", StringComparison.Ordinal);
    }

    private static TlsResolverKind GetResolverKind(TlsAccessModel model) => model switch
    {
        TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic => TlsResolverKind.TlsGetAddr,
        TlsAccessModel.TlsDesc => TlsResolverKind.TlsDesc,
        _ => TlsResolverKind.None,
    };

    private static int FindMnemonic(IReadOnlyList<SemanticInstruction> instructions, string mnemonic) =>
        instructions.ToList().FindIndex(instruction =>
            string.Equals(instruction.Mnemonic, mnemonic, StringComparison.OrdinalIgnoreCase));

    private static bool TryAdd(ulong left, ulong right, out ulong value)
    {
        if (right > ulong.MaxValue - left)
        {
            value = 0;
            return false;
        }

        value = left + right;
        return true;
    }

    private static TlsSequenceRecognitionResult Failure(DiagnosticBag diagnostics) =>
        new(null, diagnostics.ToArray());
}
