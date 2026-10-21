using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Protection;

namespace UrProtect.Core.Application.Rehydration;

/// <summary>Re-derives external provider and consumer proofs at the rehydration boundary.</summary>
internal static class SemanticExternalJumpTablePublicationValidator
{
    private const ulong MaximumOutputInstructions = 65_536;
    private static readonly SemanticExternalProviderTableIdentity ProviderTableIdentity =
        new("external-provider-table");

    public static bool ValidateSourceAndProvider(
        ElfFile source,
        ProtectedImageDocument document,
        SemanticPlanSnapshot snapshot,
        ExternalJumpTableProviderInput? providerInput,
        DiagnosticBag diagnostics,
        out Aarch64FunctionAnalysis? validatedAnalysis)
    {
        validatedAnalysis = null;
        ArgumentNullException.ThrowIfNull(source);
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(diagnostics);

        var extensions = snapshot.Extensions.OfType<SemanticExternalJumpTableExtension>().ToArray();
        if (extensions.Length == 0)
        {
            return true;
        }

        if (extensions.Length != 1)
        {
            Error(diagnostics, "Rehydration supports exactly one external provider table per semantic snapshot.");
            return false;
        }

        var extension = extensions[0];
        var consumerExtensions = snapshot.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>()
            .Where(consumer => consumer.ProviderTableIdentity == extension.TableIdentity
                && string.Equals(consumer.ProviderSha256, extension.ProviderSha256, StringComparison.Ordinal))
            .ToArray();
        if (consumerExtensions.Length != 1)
        {
            Error(diagnostics, "An external-provider semantic snapshot is missing its unique linked selected-consumer owner proof.");
            return false;
        }

        var storedProof = consumerExtensions[0].ConsumerProof;

        if (providerInput is null)
        {
            Error(diagnostics, "An external-provider semantic snapshot requires matching trusted host provider input before Native Image publication.");
            return false;
        }

        var providerSnapshot = ExternalJumpTableProviderFileReader.Read(providerInput);
        diagnostics.AddRange(providerSnapshot.Diagnostics);
        if (!providerSnapshot.IsSuccess || providerSnapshot.Bytes is null)
        {
            return false;
        }

        var providerRead = SemanticExternalJumpTableProviderReader.ReadPrivateSnapshot(
            providerSnapshot.Bytes,
            providerInput.ExpectedSoname,
            providerInput.ExpectedBuildIdHex,
            providerInput.ExpectedSha256,
            ProviderTableIdentity);
        diagnostics.AddRange(providerRead.Diagnostics);
        if (!providerRead.IsSuccess
            || providerRead.Extension is not { } pinnedExtension
            || providerRead.CreateConsumerProofInput() is not { } providerFacts)
        {
            return false;
        }

        if (!SameProviderFacts(extension, pinnedExtension))
        {
            Error(diagnostics, "The provider facts retained in the Protected Image do not match the independently pinned provider snapshot.");
            return false;
        }

        var sourceFunctions = source.FunctionSymbols
            .Where(function => function.Table == storedProof.SelectedFunction.Table
                && function.TableIndex == storedProof.SelectedFunction.TableIndex)
            .ToArray();
        var matchingFunction = sourceFunctions.Length == 1
            && sourceFunctions[0] == storedProof.SelectedFunction
                ? sourceFunctions[0]
                : (ElfFunctionSymbol?)null;
        var selectedRegions = document.Operations.OfType<ProtectedImageEmitRegion>()
            .Where(region => region.SourceAddress.Value == storedProof.SelectedFunction.Value
                && region.SourceSize == storedProof.SelectedFunction.Size)
            .ToArray();
        if (matchingFunction is not { } function || selectedRegions.Length != 1)
        {
            Error(
                diagnostics,
                "The external consumer proof does not bind one exact parsed source function and selected emit region.",
                storedProof.SelectedFunction.Value);
            return false;
        }

        var analysis = new Aarch64FunctionAnalyzer().AnalyzeWithExternalProvider(source, function, providerFacts);
        if (!analysis.IsComplete || analysis.ExternalJumpTableConsumerProofs.Count != 1)
        {
            diagnostics.AddRange(analysis.Diagnostics.Where(diagnostic => diagnostic.IsError));
            Error(
                diagnostics,
                "The selected AArch64 consumer, GOT owner, signed-32 chain, or safe default cannot be independently rederived from the source ELF.",
                storedProof.BranchAddress);
            return false;
        }

        var rederivedProof = analysis.ExternalJumpTableConsumerProofs[0];
        if (!SameConsumerProof(storedProof, rederivedProof)
            || !SameConsumerProofProvider(storedProof.ProviderFacts, providerFacts))
        {
            Error(
                diagnostics,
                "The external consumer proof retained in the Protected Image differs from the proof rederived from the pinned provider and source ELF.",
                storedProof.BranchAddress);
            return false;
        }

        // Project from the independently decoded source, not from retained operands,
        // targets, or fixups. The canonical owner compares every source field,
        // including fixup count/uniqueness, address/file/range, original encoding,
        // kind, exact target and expression (place/scale/page/addend/target).
        var projected = Aarch64SemanticPlanFactory.Create(
            analysis,
            options: new Aarch64SemanticPlanFactoryOptions(
                loadMap: source.LoadMap,
                extensions: new[] { pinnedExtension }));
        var expected = projected.Plan is { } plan
            ? SemanticPlanSnapshotCodec.Create(new SemanticRewritePlan(
                snapshot.AddressMap,
                plan.Instructions,
                plan.Fixups,
                snapshot.Extensions,
                snapshot.Diagnostics))
            : null;
        if (!projected.IsSuccess
            || expected is not { IsSuccess: true, Snapshot: { } expectedSnapshot }
            || !expectedSnapshot.CanonicalBytes.AsSpan().SequenceEqual(snapshot.CanonicalBytes))
        {
            Error(diagnostics, "The external consumer semantic instructions or unique exact fixups differ from the source-derived projection.", rederivedProof.GotPageProducerAddress);
            return false;
        }

        if (!ValidatePreservedGotMap(source, snapshot, rederivedProof)
            || !TryGetLogicalChain(source, snapshot, rederivedProof, out var functionRow, out var chain)
            || functionRow.OutputRange.Size != (ulong)selectedRegions[0].CodeBytes.Length
            // The single selected region is emitted at layout-neutral origin 0.
            // Snapshot ranges retain the source-domain anchor for offsets; they
            // are not the PC used to encode these pre-placement ADRP bytes.
            || !ValidateChain(source, selectedRegions[0].CodeBytes, functionRow.OutputRange, chain, rederivedProof, codeBaseAddress: 0))
        {
            Error(diagnostics, "The external consumer producer chain or preserved in-consumer GOT output mapping is inconsistent with the source proof.", rederivedProof.GotPageProducerAddress);
            return false;
        }

        validatedAnalysis = analysis;
        return !diagnostics.HasErrors;
    }

    public static bool ValidateRehydratedImage(
        ElfFile source,
        ElfFile output,
        ElfLayoutPlan layoutPlan,
        SemanticPlanSnapshot? snapshot,
        Aarch64FunctionAnalysis? validatedAnalysis,
        DiagnosticBag diagnostics)
    {
        if (validatedAnalysis is null)
        {
            return true;
        }

        if (!validatedAnalysis.IsComplete || validatedAnalysis.ExternalJumpTableConsumerProofs.Count != 1)
        {
            Error(diagnostics, "The final external consumer has no independently validated source analysis.");
            return false;
        }

        var proof = validatedAnalysis.ExternalJumpTableConsumerProofs[0];
        if (snapshot is null
            || !TryGetLogicalChain(source, snapshot, proof, out var functionRow, out var logicalChain))
        {
            Error(diagnostics, "The final external consumer has no exact source-derived logical producer mapping.", proof.GotPageProducerAddress);
            return false;
        }

        var physicalRegions = layoutPlan.AddressMap.Where(entry =>
            entry.SourceRange is { HasVirtualAddress: true } range
            && range.FileOffset == functionRow.SourceRange.FileOffset
            && range.VirtualAddress == functionRow.SourceRange.VirtualAddress
            && range.Size == functionRow.SourceRange.Size
            && entry.OutputRange.Size == functionRow.OutputRange.Size).ToArray();
        if (physicalRegions.Length != 1)
        {
            Error(diagnostics, "The final external consumer has no unique physical emitted-function placement.", proof.GotPageProducerAddress);
            return false;
        }

        var physical = physicalRegions[0].OutputRange;
        if (!physical.HasVirtualAddress
            || !TryGetExecutableBytes(output, physical.VirtualAddress, physical.Size, out var fileOffset, out var bytes)
            || fileOffset != physical.FileOffset)
        {
            Error(diagnostics, "The final external consumer placement is not file-backed executable output.", proof.GotPageProducerAddress);
            return false;
        }

        var physicalRange = new SemanticSourceRange(physical.FileOffset, physical.VirtualAddress, physical.Size);
        var physicalChain = new List<SemanticSourceRange>(logicalChain.Length);
        foreach (var instruction in logicalChain)
        {
            var delta = instruction.VirtualAddress.Value - functionRow.OutputRange.VirtualAddress.Value;
            if (physical.VirtualAddress.Value > ulong.MaxValue - delta
                || physical.FileOffset.Value > ulong.MaxValue - delta)
            {
                Error(diagnostics, "The final external consumer producer mapping overflows.", proof.GotPageProducerAddress);
                return false;
            }

            physicalChain.Add(new SemanticSourceRange(
                new FileOffset(physical.FileOffset.Value + delta),
                new VirtualAddress(physical.VirtualAddress.Value + delta),
                sizeof(uint)));
        }

        var decoder = new AsmStoneAdapter();
        var branchAddresses = new List<ulong>();
        for (var offset = 0; offset < bytes.Length; offset += sizeof(uint))
        {
            var address = physical.VirtualAddress.Value + (ulong)offset;
            var decoded = decoder.Decode(BinaryPrimitives.ReadUInt32LittleEndian(bytes.Span.Slice(offset, sizeof(uint))), address);
            if (!decoded.IsSuccess || decoded.Instruction is null)
            {
                Error(diagnostics, "The final external consumer contains an undecodable emitted instruction.", address);
                return false;
            }

            if (decoded.Instruction.ControlFlow == Aarch64ControlFlowKind.IndirectBranch
                && string.Equals(decoded.Instruction.Mnemonic, "BR", StringComparison.OrdinalIgnoreCase))
            {
                branchAddresses.Add(address);
            }
        }

        var entrySymbols = output.FunctionSymbols.Where(symbol =>
            symbol.Table == proof.SelectedFunction.Table && symbol.TableIndex == proof.SelectedFunction.TableIndex).ToArray();

        // Counting BRs or finding a CFG path is insufficient: a forged image can
        // replace the live BR with RET (or route through an always-false edge)
        // and retain one unreachable, perfectly encoded dispatch. Reuse the
        // source-owned emitter at the physical placement to bind all dispatcher,
        // bounds, default, and producer bytes and their actual offsets.
        if (!new FunctionProtectionService().TryReemitExternalConsumer(
                source, validatedAnalysis, physical.VirtualAddress.Value,
                out var expectedBytes, out var expectedOffsets)
            || !bytes.Span.SequenceEqual(expectedBytes)
            || proof.ProducerAddresses.Where((address, index) =>
                !expectedOffsets.TryGetValue(address, out var offset)
                || physicalChain[index].VirtualAddress.Value - physical.VirtualAddress.Value != offset).Any()
            || branchAddresses.Count != 1
            || branchAddresses[0] != physicalChain[^1].VirtualAddress.Value
            || entrySymbols.Length != 1
            || entrySymbols[0] != proof.SelectedFunction
            || !TryReadWord(output, new VirtualAddress(proof.SelectedFunction.Value), out var entryWord)
            || decoder.Decode(entryWord, proof.SelectedFunction.Value).Instruction is not
                { ControlFlow: Aarch64ControlFlowKind.DirectBranch, DirectTarget: { } entryTarget }
            || entryTarget != physical.VirtualAddress.Value
            || !ValidateChain(source, bytes, physicalRange, physicalChain, proof, codeBaseAddress: physical.VirtualAddress.Value)
            || !ValidateFinalGotOwner(source, output, proof, physicalChain))
        {
            Error(diagnostics, "The final external consumer instruction/reference chain does not reach its proven unchanged in-consumer GOT slot.", proof.GotPageProducerAddress);
            return false;
        }

        return !diagnostics.HasErrors;
    }

    private static bool ValidatePreservedGotMap(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        Aarch64ExternalJumpTableConsumerProof proof)
    {
        var gotRange = new SemanticSourceRange(proof.GotSlotFileOffset, proof.GotSlotAddress, sizeof(ulong));
        var page = new VirtualAddress(proof.GotSlotAddress.Value & ~0xFFFUL);
        if (!snapshot.AddressMap.TryMapSourceRange(gotRange, SemanticEntityKind.RelocationTarget, out var mappedGot)
            || mappedGot != gotRange
            || !snapshot.AddressMap.TryMapSourceAddress(proof.GotSlotAddress, out var gotAddress)
            || gotAddress != proof.GotSlotAddress
            || !snapshot.AddressMap.TryMapSourceAddress(page, SemanticEntityKind.RelocationTarget, out var mappedPage)
            || mappedPage != page
            || !snapshot.AddressMap.TryMapSourceAddress(page, out var resolvedPage)
            || resolvedPage != page)
        {
            return false;
        }

        foreach (var entry in snapshot.AddressMap.Entries.Where(entry =>
                     Contains(entry.SourceRange.VirtualAddress.Value, entry.SourceRange.Size, page.Value, 1)
                     || Contains(entry.SourceRange.VirtualAddress.Value, entry.SourceRange.Size, proof.GotSlotAddress.Value, sizeof(ulong))))
        {
            if (entry.SourceRange != entry.OutputRange)
            {
                return false;
            }

            // A page anchor may precede the file-backed PT_LOAD. Its only use is
            // the preserved page VA; actual pointer storage must map via LoadMap.
            if (source.LoadMap.TryVirtualAddressToFileOffset(entry.SourceRange.VirtualAddress, entry.SourceRange.Size, out var offset)
                && offset != entry.SourceRange.FileOffset)
            {
                return false;
            }
        }

        return source.LoadMap.TryVirtualAddressToFileOffset(proof.GotSlotAddress, sizeof(ulong), out var gotOffset)
            && gotOffset == proof.GotSlotFileOffset;
    }

    private static bool TryGetLogicalChain(
        ElfFile source,
        SemanticPlanSnapshot snapshot,
        Aarch64ExternalJumpTableConsumerProof proof,
        out AddressMapEntry function,
        out SemanticSourceRange[] chain)
    {
        function = null!;
        chain = Array.Empty<SemanticSourceRange>();
        if (!source.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(proof.SelectedFunction.Value), proof.SelectedFunction.Size, out var functionOffset))
        {
            return false;
        }

        var sourceRange = new SemanticSourceRange(functionOffset, new VirtualAddress(proof.SelectedFunction.Value), proof.SelectedFunction.Size);
        var functions = snapshot.AddressMap.Functions.Where(entry => entry.SourceRange == sourceRange).ToArray();
        if (functions.Length != 1
            || functions[0].OutputRange.Size == 0
            || functions[0].OutputRange.Size % sizeof(uint) != 0
            || functions[0].OutputRange.Size / sizeof(uint) > MaximumOutputInstructions
            || !functions[0].OutputRange.TryGetFileEnd(out _)
            || !functions[0].OutputRange.TryGetVirtualEnd(out _))
        {
            return false;
        }

        function = functions[0];
        var mapped = new List<SemanticSourceRange>();
        foreach (var address in proof.ProducerAddresses)
        {
            var va = new VirtualAddress(address);
            if (!source.LoadMap.TryVirtualAddressToFileOffset(va, sizeof(uint), out var offset)
                || !snapshot.AddressMap.TryGet(SemanticEntityId.Instruction(va), out var row)
                || row.SourceRange != new SemanticSourceRange(offset, va, sizeof(uint))
                || row.OutputRange.Size != sizeof(uint)
                || !Contains(function.OutputRange.VirtualAddress.Value, function.OutputRange.Size, row.OutputRange.VirtualAddress.Value, sizeof(uint))
                || !Contains(function.OutputRange.FileOffset.Value, function.OutputRange.Size, row.OutputRange.FileOffset.Value, sizeof(uint))
                || row.OutputRange.FileOffset.Value - function.OutputRange.FileOffset.Value
                    != row.OutputRange.VirtualAddress.Value - function.OutputRange.VirtualAddress.Value
                || (mapped.Count > 0 && row.OutputRange.VirtualAddress.Value != mapped[^1].VirtualAddress.Value + sizeof(uint)))
            {
                return false;
            }

            mapped.Add(row.OutputRange);
        }

        chain = mapped.ToArray();
        return chain.Length == 5;
    }

    private static bool ValidateChain(
        ElfFile source,
        ReadOnlyMemory<byte> functionBytes,
        SemanticSourceRange functionRange,
        IReadOnlyList<SemanticSourceRange> chain,
        Aarch64ExternalJumpTableConsumerProof proof,
        ulong codeBaseAddress)
    {
        var encoder = new Aarch64InstructionEncoder();
        var decoder = new AsmStoneAdapter();
        ulong? page = null;
        for (var index = 0; index < chain.Count; index++)
        {
            var offset = chain[index].VirtualAddress.Value - functionRange.VirtualAddress.Value;
            if (offset > (ulong)functionBytes.Length
                || sizeof(uint) > (ulong)functionBytes.Length - offset
                || codeBaseAddress > ulong.MaxValue - offset
                || !TryReadWord(source, new VirtualAddress(proof.ProducerAddresses[index]), out var sourceWord))
            {
                return false;
            }

            var address = codeBaseAddress + offset;
            var expectedWord = sourceWord;
            if (index == 0)
            {
                var encoded = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                    sourceWord,
                    proof.GotPageProducerAddress,
                    address,
                    Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                    proof.GotSlotAddress.Value & ~0xFFFUL));
                if (!encoded.IsSuccess)
                {
                    return false;
                }

                expectedWord = encoded.Encoding;
            }

            var word = BinaryPrimitives.ReadUInt32LittleEndian(functionBytes.Span.Slice(checked((int)offset), sizeof(uint)));
            var decoded = decoder.Decode(word, address);
            if (word != expectedWord || !decoded.IsSuccess || decoded.Instruction is null)
            {
                return false;
            }

            if (index == 0)
            {
                page = decoded.Instruction.DirectTarget;
            }
            else if (index == 1)
            {
                var memories = decoded.Instruction.Operands.Where(operand => operand.Memory is not null).Select(operand => operand.Memory!).ToArray();
                if (memories.Length != 1
                    || memories[0].AccessSize != sizeof(ulong)
                    || memories[0].Offset < 0
                    || page is not { } gotPage
                    || gotPage > ulong.MaxValue - (ulong)memories[0].Offset
                    || gotPage + (ulong)memories[0].Offset != proof.GotSlotAddress.Value)
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool ValidateFinalGotOwner(
        ElfFile source,
        ElfFile output,
        Aarch64ExternalJumpTableConsumerProof proof,
        IReadOnlyList<SemanticSourceRange> chain) =>
        output.DynamicMetadata.NeededLibraries.SequenceEqual(source.DynamicMetadata.NeededLibraries, StringComparer.Ordinal)
        && Aarch64IndirectCallProofAnalyzer.TryResolveImportOwner(
            output,
            proof.ImportOwner.Relocation,
            proof.GotSlotAddress.Value,
            proof.GotSlotAddress.Value & ~0xFFFUL,
            chain[0].VirtualAddress.Value,
            chain[1].VirtualAddress.Value,
            out var owner,
            out _)
        && owner == proof.ImportOwner with
        {
            AddressPageProducerAddress = chain[0].VirtualAddress.Value,
            PointerLoadProducerAddress = chain[1].VirtualAddress.Value,
        }
        && output.RelaRelocations.Count(relocation => relocation.SymbolIndex == proof.ImportOwner.SymbolIndex) == 1
        && output.DynamicSymbols[checked((int)proof.ImportOwner.SymbolIndex)] == source.DynamicSymbols[checked((int)proof.ImportOwner.SymbolIndex)]
        && output.LoadMap.TryVirtualAddressToFileOffset(proof.GotSlotAddress, sizeof(ulong), out var offset)
        && offset == proof.GotSlotFileOffset
        && offset.Value <= (ulong)output.Bytes.Length
        && sizeof(ulong) <= (ulong)output.Bytes.Length - offset.Value
        && source.Bytes.Span.Slice(checked((int)proof.GotSlotFileOffset.Value), sizeof(ulong))
            .SequenceEqual(output.Bytes.Span.Slice(checked((int)offset.Value), sizeof(ulong)));

    private static bool TryGetExecutableBytes(ElfFile file, VirtualAddress address, ulong size, out FileOffset offset, out ReadOnlyMemory<byte> bytes)
    {
        bytes = default;
        if (!file.LoadMap.TryVirtualAddressToFileOffset(address, size, out offset)
            || file.LoadMap.Segments.Count(segment => segment.IsExecutable && segment.ContainsVirtualAddress(address.Value, size)) != 1
            || offset.Value > (ulong)file.Bytes.Length
            || size > (ulong)file.Bytes.Length - offset.Value)
        {
            return false;
        }

        bytes = file.Bytes.Slice(checked((int)offset.Value), checked((int)size));
        return true;
    }

    private static bool TryReadWord(ElfFile file, VirtualAddress address, out uint word)
    {
        word = 0;
        if (!TryGetExecutableBytes(file, address, sizeof(uint), out _, out var bytes))
        {
            return false;
        }

        word = BinaryPrimitives.ReadUInt32LittleEndian(bytes.Span);
        return true;
    }

    private static bool Contains(ulong start, ulong size, ulong address, ulong width) =>
        address >= start && address - start <= size && width <= size - (address - start);

    private static bool SameProviderFacts(
        SemanticExternalJumpTableExtension first,
        SemanticExternalJumpTableExtension second)
    {
        return first.TableIdentity == second.TableIdentity
            && string.Equals(first.ProviderSoname, second.ProviderSoname, StringComparison.Ordinal)
            && string.Equals(first.ProviderBuildIdHex, second.ProviderBuildIdHex, StringComparison.Ordinal)
            && string.Equals(first.ProviderSha256, second.ProviderSha256, StringComparison.Ordinal)
            && first.ProviderFileSize == second.ProviderFileSize
            && first.Encoding == second.Encoding
            && first.TableObject == second.TableObject
            && first.TableBytesSpan.SequenceEqual(second.TableBytesSpan)
            && first.TargetSymbols.OrderBy(symbol => symbol.SymbolTable)
                .ThenBy(symbol => symbol.SymbolIndex)
                .ThenBy(symbol => symbol.Name, StringComparer.Ordinal)
                .SequenceEqual(second.TargetSymbols.OrderBy(symbol => symbol.SymbolTable)
                    .ThenBy(symbol => symbol.SymbolIndex)
                    .ThenBy(symbol => symbol.Name, StringComparer.Ordinal))
            && first.Entries.OrderBy(entry => entry.Index)
                .SequenceEqual(second.Entries.OrderBy(entry => entry.Index));
    }

    private static bool SameConsumerProof(
        Aarch64ExternalJumpTableConsumerProof first,
        Aarch64ExternalJumpTableConsumerProof second) =>
        first.SelectedFunction == second.SelectedFunction
        && first.CompareAddress == second.CompareAddress
        && first.BoundsBranchAddress == second.BoundsBranchAddress
        && first.SafeDefaultAddress == second.SafeDefaultAddress
        && first.SafeDefaultPathAddresses.SequenceEqual(second.SafeDefaultPathAddresses)
        && first.GotPageProducerAddress == second.GotPageProducerAddress
        && first.GotLoadProducerAddress == second.GotLoadProducerAddress
        && first.IndexedLoadAddress == second.IndexedLoadAddress
        && first.TableBaseAddAddress == second.TableBaseAddAddress
        && first.BranchAddress == second.BranchAddress
        && first.ProducerAddresses.SequenceEqual(second.ProducerAddresses)
        && first.IndexRegister == second.IndexRegister
        && first.GotPointerRegister == second.GotPointerRegister
        && first.LoadedDisplacementRegister == second.LoadedDisplacementRegister
        && first.TargetRegister == second.TargetRegister
        && first.EntryWidth == second.EntryWidth
        && first.IsSigned == second.IsSigned
        && first.IndexScaleShift == second.IndexScaleShift
        && first.LowerBound == second.LowerBound
        && first.UpperBound == second.UpperBound
        && first.GotSlotAddress == second.GotSlotAddress
        && first.GotSlotFileOffset == second.GotSlotFileOffset
        && first.ImportOwner == second.ImportOwner;

    private static bool SameConsumerProofProvider(
        Aarch64ExternalJumpTableProviderFacts first,
        Aarch64ExternalJumpTableProviderFacts second)
    {
        return string.Equals(first.TableIdentity, second.TableIdentity, StringComparison.Ordinal)
            && string.Equals(first.ProviderSoname, second.ProviderSoname, StringComparison.Ordinal)
            && string.Equals(first.ProviderBuildIdHex, second.ProviderBuildIdHex, StringComparison.Ordinal)
            && string.Equals(first.ProviderSha256, second.ProviderSha256, StringComparison.Ordinal)
            && string.Equals(first.TableObjectName, second.TableObjectName, StringComparison.Ordinal)
            && first.TableObjectSize == second.TableObjectSize
            && string.Equals(first.TableBytesSha256, second.TableBytesSha256, StringComparison.Ordinal)
            && first.TargetSymbols.OrderBy(target => target.Index)
                .SequenceEqual(second.TargetSymbols.OrderBy(target => target.Index));
    }

    private static void Error(DiagnosticBag diagnostics, string message, ulong? offset = null) =>
        diagnostics.Error(DiagnosticCode.SemanticPlanSnapshotMalformed, message, offset);
}
