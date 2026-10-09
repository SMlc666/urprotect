using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.SemanticPlanning;

namespace UrProtect.Core.ElfLayout;

public static class ElfLayoutPlanner
{
    private const uint GeneratedSegmentPermissions = ElfConstants.PfR | ElfConstants.PfX;
    private static readonly int[] TlsDescPairOrdinals = { 0, 1, 2, 3 };
    private static readonly uint?[] TlsDescRelocationTypes =
    {
        ElfConstants.RArm64TlsDescAdrPage21,
        ElfConstants.RArm64TlsDescLd64Lo12,
        ElfConstants.RArm64TlsDescAddLo12,
        ElfConstants.RArm64TlsDescCall,
    };

    public static ElfLayoutPlanningResult Plan(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        IEnumerable<ElfLayoutRegionRequest> regionRequests,
        IEnumerable<ElfLayoutBranchRequest> branchRequests,
        ElfLayoutOptions? options = null,
        IEnumerable<ElfLayoutTlsFixupRequest>? tlsFixupRequests = null)
    {
        ArgumentNullException.ThrowIfNull(sourceFile);
        ArgumentNullException.ThrowIfNull(regionRequests);
        ArgumentNullException.ThrowIfNull(branchRequests);

        var diagnostics = new DiagnosticBag();
        options ??= ElfLayoutOptions.Default;
        ValidateOptions(options, diagnostics);
        var maximumRequests = Math.Max(options.MaximumEditCount, 1);
        var regions = ReadBounded(regionRequests, maximumRequests, out var regionsExceeded);
        var branches = ReadBounded(branchRequests, maximumRequests, out var branchesExceeded);
        var tlsFixups = ReadBounded(tlsFixupRequests ?? Array.Empty<ElfLayoutTlsFixupRequest>(), maximumRequests, out var tlsFixupsExceeded);
        if (regionsExceeded || branchesExceeded || tlsFixupsExceeded)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutOutputLimitExceeded, "The layout request stream exceeds its configured edit bound.");
        }

        var sourceLength = (ulong)sourceBytes.Length;
        if (sourceFile.Bytes.Length != sourceBytes.Length
            || !sourceFile.Bytes.Span.SequenceEqual(sourceBytes.Span))
        {
            diagnostics.Error(
                DiagnosticCode.ElfLayoutSourceMismatch,
                "The parsed ELF snapshot does not match the layout source snapshot.");
        }

        var sourceSha256 = Sha256(sourceBytes.Span);
        ValidateSource(sourceFile, sourceLength, options, diagnostics);
        ValidateRequests(sourceFile, sourceLength, regions, branches, options, diagnostics);
        ValidateTlsFixupRequests(sourceFile, regions, tlsFixups, diagnostics);
        if (diagnostics.HasErrors)
        {
            return new ElfLayoutPlanningResult(null, null, diagnostics.ToArray());
        }

        var strategies = options.RequestedStrategy is ElfLayoutStrategy requested
            ? new[] { requested }
            : new[]
            {
                ElfLayoutStrategy.ExistingExecutableLoadExtension,
                ElfLayoutStrategy.AvailableProgramHeaderSlot,
                ElfLayoutStrategy.RelocatedProgramHeaderTable,
            };
        var candidates = new List<LayoutCandidate>(strategies.Length);
        var candidateDiagnostics = new List<Diagnostic>();
        foreach (var strategy in strategies)
        {
            if (TryBuildCandidate(
                    sourceBytes,
                    sourceFile,
                    sourceLength,
                    sourceSha256,
                    regions,
                    branches,
                    tlsFixups,
                    options,
                    strategy,
                    out var candidate,
                    out var rejected))
            {
                candidates.Add(candidate!);
            }
            else
            {
                candidateDiagnostics.AddRange(rejected);
            }
        }

        if (candidates.Count == 0)
        {
            diagnostics.AddRange(candidateDiagnostics);
            if (!diagnostics.HasErrors)
            {
                diagnostics.Error(
                    DiagnosticCode.RehydrationLayoutUnavailable,
                    "No bounded ELF layout strategy can place the requested transformed code.");
            }

            return new ElfLayoutPlanningResult(null, null, diagnostics.ToArray());
        }

        var selected = candidates
            .OrderBy(candidate => candidate.Score.TableRelocation)
            .ThenBy(candidate => candidate.Score.ProgramHeaderCountDelta)
            .ThenBy(candidate => candidate.Score.MetadataHeaderEdits)
            .ThenBy(candidate => candidate.Score.PaddingBytes)
            .ThenBy(candidate => candidate.Score.StrategyRank)
            .First();
        var evidence = CreateEvidence(selected.Plan);
        return new ElfLayoutPlanningResult(selected.Plan, evidence, diagnostics.ToArray());
    }

    public static ElfLayoutPlanningResult Plan(
        ElfFile sourceFile,
        IEnumerable<ElfLayoutRegionRequest> regionRequests,
        IEnumerable<ElfLayoutBranchRequest> branchRequests,
        ElfLayoutOptions? options = null,
        IEnumerable<ElfLayoutTlsFixupRequest>? tlsFixupRequests = null) =>
        Plan(sourceFile.Bytes, sourceFile, regionRequests, branchRequests, options, tlsFixupRequests);

    public static ElfLayoutPlanningResult CreatePlan(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        IEnumerable<ElfLayoutRegionRequest> regionRequests,
        IEnumerable<ElfLayoutBranchRequest> branchRequests,
        ElfLayoutOptions? options = null,
        IEnumerable<ElfLayoutTlsFixupRequest>? tlsFixupRequests = null) =>
        Plan(sourceBytes, sourceFile, regionRequests, branchRequests, options, tlsFixupRequests);

    private static bool TryBuildCandidate(
        ReadOnlyMemory<byte> sourceBytes,
        ElfFile sourceFile,
        ulong sourceLength,
        string sourceSha256,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutBranchRequest> branches,
        IReadOnlyList<ElfLayoutTlsFixupRequest> tlsFixups,
        ElfLayoutOptions options,
        ElfLayoutStrategy strategy,
        out LayoutCandidate? candidate,
        out IReadOnlyList<Diagnostic> rejected)
    {
        var diagnostics = new DiagnosticBag();
        candidate = null;
        rejected = Array.Empty<Diagnostic>();
        try
        {
            if (!TryGetProgramHeaderTableRange(sourceFile, sourceLength, out var oldTable, out var tableSize))
            {
                diagnostics.Error(
                    DiagnosticCode.TableOutOfBounds,
                    "The source program-header table cannot be represented by the bounded layout planner.",
                    sourceFile.Header.ProgramHeaderOffset);
                rejected = diagnostics.ToArray();
                return false;
            }

            var sourceHeaders = sourceFile.ProgramHeaders.ToArray();
            var plannedHeaders = sourceHeaders.ToList();
            var programHeaderCount = sourceHeaders.Length;
            var segmentAlignment = options.SegmentAlignment;
            var segmentFileStart = 0UL;
            var segmentVirtualStart = 0UL;
            var codeFileStart = 0UL;
            var codeVirtualStart = 0UL;
            var tableFileStart = sourceFile.Header.ProgramHeaderOffset;
            var tableVirtualAddress = oldTable.VirtualAddress.Value;
            var tableHasVirtualAddress = oldTable.HasVirtualAddress;
            var tableOutputSize = tableSize;
            var changedHeaderIndex = -1;
            var extensionHeader = default(ProgramHeader);
            var isExtension = strategy == ElfLayoutStrategy.ExistingExecutableLoadExtension;
            var isRelocation = strategy == ElfLayoutStrategy.RelocatedProgramHeaderTable;

            if (isExtension)
            {
                if (!TryFindExtensionHeader(sourceFile, sourceLength, out changedHeaderIndex, out extensionHeader))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationLayoutUnavailable,
                        "No terminal executable PT_LOAD can be safely extended without mapping unrelated source bytes.");
                    rejected = diagnostics.ToArray();
                    return false;
                }

                if (extensionHeader.Alignment > options.MaximumAlignment)
                {
                    diagnostics.Error(
                        DiagnosticCode.InvalidAlignment,
                        "The existing executable PT_LOAD alignment exceeds the configured layout bound.",
                        extensionHeader.Offset);
                    rejected = diagnostics.ToArray();
                    return false;
                }

                segmentFileStart = sourceLength;
                if (!TryAdd(extensionHeader.VirtualAddress, extensionHeader.FileSize, out codeVirtualStart))
                {
                    diagnostics.Error(DiagnosticCode.AddressOverflow, "The executable PT_LOAD extension address overflowed.");
                    rejected = diagnostics.ToArray();
                    return false;
                }

                codeFileStart = sourceLength;
                segmentVirtualStart = extensionHeader.VirtualAddress;
            }
            else
            {
                if (!TryGetAlignedPlacement(
                        sourceFile,
                        sourceLength,
                        options,
                        out segmentFileStart,
                        out segmentVirtualStart,
                        diagnostics))
                {
                    rejected = diagnostics.ToArray();
                    return false;
                }

                codeFileStart = segmentFileStart;
                codeVirtualStart = segmentVirtualStart;
                if (isRelocation)
                {
                    if (programHeaderCount >= options.MaximumProgramHeaderCount
                        || programHeaderCount >= ushort.MaxValue)
                    {
                        diagnostics.Error(
                            DiagnosticCode.RehydrationLayoutUnavailable,
                            "The relocated program-header table would exceed the bounded program-header count.");
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    var newCount = checked(programHeaderCount + 1);
                    tableOutputSize = checked((ulong)newCount * sourceFile.Header.ProgramHeaderEntrySize);
                    if (!TryAdd(segmentFileStart, tableOutputSize, out var codeAfterTable)
                        || !TryAlignUp(codeAfterTable, options.CodeAlignment, out codeFileStart)
                        || codeFileStart < segmentFileStart)
                    {
                        diagnostics.Error(DiagnosticCode.AddressOverflow, "The relocated program-header table placement overflowed.");
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    codeVirtualStart = checked(segmentVirtualStart + (codeFileStart - segmentFileStart));
                    tableFileStart = segmentFileStart;
                    tableVirtualAddress = segmentVirtualStart;
                    tableHasVirtualAddress = true;
                    programHeaderCount = newCount;
                }
                else if (!TryFindNullHeader(sourceHeaders, out changedHeaderIndex))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationLayoutUnavailable,
                        "The source ELF has no PT_NULL program-header candidate for the generated executable region.");
                    rejected = diagnostics.ToArray();
                    return false;
                }
            }

            var placements = new List<ElfLayoutPlacement>(regions.Count + options.MaximumVeneerCount);
            var tlsFixupDecisions = new List<ElfLayoutTlsFixupDecision>(tlsFixups.Count);
            var addressMap = new List<ElfLayoutAddressMapEntry>(regions.Count + options.MaximumVeneerCount);
            var placementByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
            var edits = new List<ElfLayoutByteEdit>();
            var cursorFile = codeFileStart;
            var cursorVirtual = codeVirtualStart;
            foreach (var region in regions.OrderBy(region => region.Identity, StringComparer.Ordinal))
            {
                var previousFileCursor = cursorFile;
                if (!TryAlignPlacementCursor(
                        ref cursorFile,
                        ref cursorVirtual,
                        region.Alignment,
                        codeFileStart,
                        codeVirtualStart,
                        diagnostics))
                {
                    rejected = diagnostics.ToArray();
                    return false;
                }

                AddPaddingEdits(edits, previousFileCursor, cursorFile, options, diagnostics);
                if (diagnostics.HasErrors)
                {
                    rejected = diagnostics.ToArray();
                    return false;
                }

                var placement = new ElfLayoutPlacement(
                    region.Identity,
                    region.SourceIdentity,
                    new FileOffset(cursorFile),
                    new VirtualAddress(cursorVirtual),
                    checked((ulong)region.CodeBytes.Length),
                    region.Permissions,
                    region.Alignment);
                placements.Add(placement);
                placementByIdentity.Add(placement.Identity, placement);
                var sourceRange = GetSourceRange(sourceFile, region.SourceAddress, region.SourceSize);
                addressMap.Add(new ElfLayoutAddressMapEntry(placement.Identity, placement.SourceIdentity, sourceRange, placement.Range));
                var materializedCode = region.CodeBytes.ToArray();
                foreach (var tlsFixup in tlsFixups.Where(request => string.Equals(
                             request.RegionIdentity,
                             region.Identity,
                             StringComparison.Ordinal)))
                {
                    if (!ApplyTlsFixup(sourceFile, region, placement, tlsFixup, materializedCode, tlsFixupDecisions, diagnostics))
                    {
                        rejected = diagnostics.ToArray();
                        return false;
                    }
                }

                edits.Add(new ElfLayoutByteEdit(placement.FileOffset, materializedCode, ElfLayoutEditKind.GeneratedCode));
                cursorFile = checked(cursorFile + placement.Size);
                cursorVirtual = checked(cursorVirtual + placement.Size);
            }

            var branchDecisions = new List<ElfBranchPlacementDecision>(branches.Count);
            var veneerByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
            var veneerRequestByIdentity = new Dictionary<string, ElfLayoutVeneerRequest>(StringComparer.Ordinal);
            var longBranchByIdentity = new Dictionary<string, ElfLayoutPlacement>(StringComparer.Ordinal);
            var longBranchRequestByIdentity = new Dictionary<string, ElfLayoutLongBranchRequest>(StringComparer.Ordinal);
            foreach (var branch in branches.OrderBy(branch => branch.Identity, StringComparer.Ordinal))
            {
                if (!placementByIdentity.TryGetValue(branch.TargetIdentity, out var targetPlacement))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationMalformed,
                        $"Branch '{branch.Identity}' refers to an unknown target placement.");
                    rejected = diagnostics.ToArray();
                    return false;
                }

                var branchAddress = checked(branch.SourceAddress.Value + branch.SourceOffset);
                if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                        new VirtualAddress(branchAddress),
                        sizeof(uint),
                        out var branchFileOffset))
                {
                    diagnostics.Error(
                        DiagnosticCode.AddressUnmapped,
                        $"Branch '{branch.Identity}' is not mapped to a file-backed executable source instruction.",
                        branchAddress);
                    rejected = diagnostics.ToArray();
                    return false;
                }

                var targetAddress = checked(targetPlacement.VirtualAddress.Value + branch.TargetOffset);
                var targetRange = new ElfLayoutRange(
                    new FileOffset(checked(targetPlacement.FileOffset.Value + branch.TargetOffset)),
                    new VirtualAddress(targetAddress),
                    sizeof(uint));
                if (branch.Encoding != ElfLayoutBranchEncodingKind.Branch26)
                {
                    diagnostics.Error(
                        DiagnosticCode.ElfLayoutUnsupported,
                        $"Branch '{branch.Identity}' uses an unsupported layout encoding.",
                        branchAddress);
                    rejected = diagnostics.ToArray();
                    return false;
                }

                if (TryEncodeBranch26(branch.Opcode, branchAddress, targetAddress, out var directEncoding, out var directDisplacement))
                {
                    var sourceRange = GetSourceRange(sourceFile, new VirtualAddress(branchAddress), sizeof(uint));
                    branchDecisions.Add(new ElfBranchPlacementDecision(
                        branch.Identity,
                        branch.SourceIdentity,
                        branch.TargetIdentity,
                        ElfLayoutBranchDecision.Direct,
                        sourceRange ?? new ElfLayoutRange(branchFileOffset, new VirtualAddress(branchAddress), sizeof(uint)),
                        targetRange,
                        directDisplacement,
                        null,
                        branch.Opcode,
                        ElfLayoutLimits.Branch26MinimumDisplacement,
                        ElfLayoutLimits.Branch26MaximumDisplacementExclusive));
                    edits.Add(new ElfLayoutByteEdit(branchFileOffset, directEncoding, ElfLayoutEditKind.BranchFixup));
                    continue;
                }

                if (branch.NearVeneer is not null)
                {
                    var veneer = branch.NearVeneer;
                    if (!string.Equals(veneer.TargetIdentity, branch.TargetIdentity, StringComparison.Ordinal))
                    {
                        diagnostics.Error(
                            DiagnosticCode.ElfLayoutMalformed,
                            $"Branch '{branch.Identity}' veneer target does not match the branch target.",
                            branchAddress);
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    ElfLayoutPlacement veneerPlacement;
                    if (veneerByIdentity.TryGetValue(veneer.Identity, out var existingVeneerPlacement))
                    {
                        if (!veneerRequestByIdentity.TryGetValue(veneer.Identity, out var existingVeneer)
                            || !EquivalentVeneerRequest(existingVeneer, veneer))
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutMalformed,
                                $"Veneer identity '{veneer.Identity}' is reused with different typed bytes or target metadata.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        veneerPlacement = existingVeneerPlacement;
                    }
                    else
                    {
                        veneerRequestByIdentity.Add(veneer.Identity, veneer);
                        if (veneerByIdentity.Count >= options.MaximumVeneerCount)
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutOutputLimitExceeded,
                                "The layout veneer count exceeds its configured bound.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        var previousFileCursor = cursorFile;
                        if (!TryAlignPlacementCursor(
                                ref cursorFile,
                                ref cursorVirtual,
                                veneer.Alignment,
                                codeFileStart,
                                codeVirtualStart,
                                diagnostics))
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        AddPaddingEdits(edits, previousFileCursor, cursorFile, options, diagnostics);
                        if (diagnostics.HasErrors)
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        veneerPlacement = new ElfLayoutPlacement(
                            veneer.Identity,
                            branch.SourceIdentity,
                            new FileOffset(cursorFile),
                            new VirtualAddress(cursorVirtual),
                            checked((ulong)veneer.CodeBytes.Length),
                            veneer.Permissions,
                            veneer.Alignment);
                        veneerByIdentity.Add(veneer.Identity, veneerPlacement);
                        placementByIdentity.Add(veneer.Identity, veneerPlacement);
                        placements.Add(veneerPlacement);
                        addressMap.Add(new ElfLayoutAddressMapEntry(
                            veneerPlacement.Identity,
                            veneerPlacement.SourceIdentity,
                            null,
                            veneerPlacement.Range));
                        edits.Add(new ElfLayoutByteEdit(
                            veneerPlacement.FileOffset,
                            veneer.CodeBytes,
                            ElfLayoutEditKind.GeneratedCode));
                        cursorFile = checked(cursorFile + veneerPlacement.Size);
                        cursorVirtual = checked(cursorVirtual + veneerPlacement.Size);
                    }

                    if (!TryEncodeBranch26(
                            branch.Opcode,
                            branchAddress,
                            veneerPlacement.VirtualAddress.Value,
                            out var veneerEncoding,
                            out var veneerDisplacement)
                        || veneerDisplacement is null
                        || (ulong)Math.Abs(veneerDisplacement.Value) > veneer.MaximumBranchDistance)
                    {
                        diagnostics.Error(
                            DiagnosticCode.ElfLayoutBranchOutOfRange,
                            $"Branch '{branch.Identity}' cannot reach its requested near veneer.",
                            branchAddress);
                        rejected = diagnostics.ToArray();
                        return false;
                    }

                    var sourceRangeForVeneer = GetSourceRange(sourceFile, new VirtualAddress(branchAddress), sizeof(uint));
                    branchDecisions.Add(new ElfBranchPlacementDecision(
                        branch.Identity,
                        branch.SourceIdentity,
                        branch.TargetIdentity,
                        ElfLayoutBranchDecision.NearVeneer,
                        sourceRangeForVeneer ?? new ElfLayoutRange(branchFileOffset, new VirtualAddress(branchAddress), sizeof(uint)),
                        veneerPlacement.Range,
                        veneerDisplacement,
                        veneer.Identity,
                        branch.Opcode,
                        ElfLayoutLimits.Branch26MinimumDisplacement,
                        ElfLayoutLimits.Branch26MaximumDisplacementExclusive));
                    edits.Add(new ElfLayoutByteEdit(branchFileOffset, veneerEncoding, ElfLayoutEditKind.BranchFixup));
                    continue;
                }

                if (branch.LongBranch is not null)
                {
                    var longBranch = branch.LongBranch;
                    ElfLayoutPlacement longPlacement;
                    if (longBranchByIdentity.TryGetValue(longBranch.Identity, out var existingLongPlacement))
                    {
                        if (!longBranchRequestByIdentity.TryGetValue(longBranch.Identity, out var existingLongBranch)
                            || !EquivalentLongBranchRequest(existingLongBranch, longBranch))
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutMalformed,
                                $"Long-branch identity '{longBranch.Identity}' is reused with different typed bytes or replacement metadata.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        longPlacement = existingLongPlacement;
                    }
                    else
                    {
                        longBranchRequestByIdentity.Add(longBranch.Identity, longBranch);
                        var previousFileCursor = cursorFile;
                        if (!TryAlignPlacementCursor(
                                ref cursorFile,
                                ref cursorVirtual,
                                longBranch.Alignment,
                                codeFileStart,
                                codeVirtualStart,
                                diagnostics))
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        AddPaddingEdits(edits, previousFileCursor, cursorFile, options, diagnostics);
                        if (diagnostics.HasErrors)
                        {
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        longPlacement = new ElfLayoutPlacement(
                            longBranch.Identity,
                            branch.SourceIdentity,
                            new FileOffset(cursorFile),
                            new VirtualAddress(cursorVirtual),
                            checked((ulong)longBranch.CodeBytes.Length),
                            longBranch.Permissions,
                            longBranch.Alignment);
                        longBranchByIdentity.Add(longBranch.Identity, longPlacement);
                        placementByIdentity.Add(longPlacement.Identity, longPlacement);
                        placements.Add(longPlacement);
                        addressMap.Add(new ElfLayoutAddressMapEntry(
                            longPlacement.Identity,
                            longPlacement.SourceIdentity,
                            null,
                            longPlacement.Range));
                        edits.Add(new ElfLayoutByteEdit(
                            longPlacement.FileOffset,
                            longBranch.CodeBytes,
                            ElfLayoutEditKind.GeneratedCode));
                        cursorFile = checked(cursorFile + longPlacement.Size);
                        cursorVirtual = checked(cursorVirtual + longPlacement.Size);
                    }

                    var longSourceRange = GetSourceRange(sourceFile, new VirtualAddress(branchAddress), sizeof(uint));
                    branchDecisions.Add(new ElfBranchPlacementDecision(
                        branch.Identity,
                        branch.SourceIdentity,
                        branch.TargetIdentity,
                        ElfLayoutBranchDecision.LongAddress,
                        longSourceRange ?? new ElfLayoutRange(branchFileOffset, new VirtualAddress(branchAddress), sizeof(uint)),
                        targetRange,
                        null,
                        longPlacement.Identity,
                        branch.Opcode,
                        ElfLayoutLimits.Branch26MinimumDisplacement,
                        ElfLayoutLimits.Branch26MaximumDisplacementExclusive));
                    if (longBranch.SourceReplacementBytes is not null)
                    {
                        if (longBranch.SourceReplacementBytes.Length == 0
                            || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                                new VirtualAddress(branchAddress),
                                checked((ulong)longBranch.SourceReplacementBytes.Length),
                                out _))
                        {
                            diagnostics.Error(
                                DiagnosticCode.ElfLayoutMalformed,
                                $"Long branch '{longBranch.Identity}' has an invalid source replacement range.",
                                branchAddress);
                            rejected = diagnostics.ToArray();
                            return false;
                        }

                        edits.Add(new ElfLayoutByteEdit(
                            branchFileOffset,
                            longBranch.SourceReplacementBytes,
                            ElfLayoutEditKind.LongBranch));
                    }

                    continue;
                }

                diagnostics.Error(
                    DiagnosticCode.ElfLayoutBranchOutOfRange,
                    $"Branch '{branch.Identity}' is outside the direct Branch26 range and has no typed relaxation.",
                    branchAddress);
                rejected = diagnostics.ToArray();
                return false;
            }

            var generatedSpanBytes = checked(cursorFile - codeFileStart);
            var generatedCodeBytes = 0UL;
            foreach (var placement in placements)
            {
                generatedCodeBytes = checked(generatedCodeBytes + placement.Size);
            }

            if (generatedCodeBytes == 0 || generatedCodeBytes > (ulong)options.MaximumGeneratedCodeBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "Generated code and typed veneers exceed the configured layout bound.");
                rejected = diagnostics.ToArray();
                return false;
            }

            var paddingBytes = 0UL;
            foreach (var padding in edits.Where(edit => edit.Kind == ElfLayoutEditKind.Padding))
            {
                paddingBytes = checked(paddingBytes + (ulong)padding.Bytes.Length);
            }
            if (paddingBytes > options.MaximumPaddingBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "Layout padding exceeds the configured bound.");
                rejected = diagnostics.ToArray();
                return false;
            }
            var segmentFileSize = isRelocation
                ? checked((codeFileStart - segmentFileStart) + generatedSpanBytes)
                : generatedSpanBytes;
            var segmentVirtualSize = segmentFileSize;
            var plannedSegment = new ProgramHeader(
                ElfConstants.PtLoad,
                isExtension ? extensionHeader.Flags : GeneratedSegmentPermissions,
                isExtension ? extensionHeader.Offset : segmentFileStart,
                isExtension ? extensionHeader.VirtualAddress : segmentVirtualStart,
                isExtension ? extensionHeader.PhysicalAddress : segmentVirtualStart,
                isExtension ? checked(extensionHeader.FileSize + generatedSpanBytes) : segmentFileSize,
                isExtension ? checked(extensionHeader.MemorySize + generatedSpanBytes) : segmentVirtualSize,
                isExtension ? extensionHeader.Alignment : segmentAlignment);

            if (isExtension || strategy == ElfLayoutStrategy.AvailableProgramHeaderSlot)
            {
                plannedHeaders[changedHeaderIndex] = plannedSegment;
            }
            else
            {
                if (sourceFile.ProgramHeaders.Any(header => header.Type == ElfConstants.PtPhdr))
                {
                    for (var index = 0; index < plannedHeaders.Count; index++)
                    {
                        if (plannedHeaders[index].Type != ElfConstants.PtPhdr)
                        {
                            continue;
                        }

                        var original = plannedHeaders[index];
                        plannedHeaders[index] = original with
                        {
                            Offset = tableFileStart,
                            VirtualAddress = tableVirtualAddress,
                            PhysicalAddress = tableVirtualAddress,
                            FileSize = tableOutputSize,
                            MemorySize = tableOutputSize,
                        };
                    }
                }

                plannedHeaders.Add(plannedSegment);
            }

            var programHeaderPlans = new List<ElfProgramHeaderPlan>(plannedHeaders.Count);
            for (var index = 0; index < plannedHeaders.Count; index++)
            {
                var original = index < sourceHeaders.Length ? sourceHeaders[index] : (ProgramHeader?)null;
                var editKind = ElfProgramHeaderEditKind.Unchanged;
                if (original is null)
                {
                    editKind = ElfProgramHeaderEditKind.NewProgramHeader;
                }
                else if (plannedHeaders[index] != original.Value)
                {
                    editKind = plannedHeaders[index].Type == ElfConstants.PtPhdr
                        ? ElfProgramHeaderEditKind.UpdatedProgramHeaderTableMapping
                        : strategy == ElfLayoutStrategy.ExistingExecutableLoadExtension
                            ? ElfProgramHeaderEditKind.ExtendedExecutableLoad
                            : ElfProgramHeaderEditKind.ReplaceAvailableSlot;
                }

                programHeaderPlans.Add(new ElfProgramHeaderPlan(index < sourceHeaders.Length ? index : null, original, plannedHeaders[index], editKind));
            }

            AddPaddingEdits(edits, sourceLength, segmentFileStart, options, diagnostics);
            if (isRelocation)
            {
                var tableBytes = SerializeProgramHeaders(plannedHeaders);
                edits.Add(new ElfLayoutByteEdit(new FileOffset(tableFileStart), tableBytes, ElfLayoutEditKind.ProgramHeaderTable));
                var newProgramHeaderOffset = new byte[sizeof(ulong)];
                BinaryPrimitives.WriteUInt64LittleEndian(newProgramHeaderOffset, tableFileStart);
                edits.Add(new ElfLayoutByteEdit(
                    new FileOffset(ElfHeaderOffsets.ProgramHeaderOffset),
                    newProgramHeaderOffset,
                    ElfLayoutEditKind.ElfHeader));
                var newProgramHeaderCount = new byte[sizeof(ushort)];
                BinaryPrimitives.WriteUInt16LittleEndian(newProgramHeaderCount, checked((ushort)plannedHeaders.Count));
                edits.Add(new ElfLayoutByteEdit(
                    new FileOffset(ElfHeaderOffsets.ProgramHeaderCount),
                    newProgramHeaderCount,
                    ElfLayoutEditKind.ElfHeader));
                AddPaddingEdits(
                    edits,
                    checked(segmentFileStart + tableOutputSize),
                    codeFileStart,
                    options,
                    diagnostics);
            }
            else
            {
                var headerOffset = checked(sourceFile.Header.ProgramHeaderOffset
                    + checked((ulong)changedHeaderIndex * sourceFile.Header.ProgramHeaderEntrySize));
                edits.Add(new ElfLayoutByteEdit(
                    new FileOffset(headerOffset),
                    SerializeProgramHeader(plannedHeaders[changedHeaderIndex]),
                    ElfLayoutEditKind.ProgramHeader));
            }

            if (diagnostics.HasErrors)
            {
                rejected = diagnostics.ToArray();
                return false;
            }

            if (edits.Count > options.MaximumEditCount)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "The layout edit count exceeds the configured bound.");
                rejected = diagnostics.ToArray();
                return false;
            }

            var outputLength = Math.Max(sourceLength, cursorFile);
            if (outputLength > options.MaximumOutputBytes || outputLength > int.MaxValue)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutOutputLimitExceeded,
                    "The planned Native Image exceeds the configured output bound.");
                rejected = diagnostics.ToArray();
                return false;
            }

            var newTable = new ElfLayoutRange(
                new FileOffset(tableFileStart),
                new VirtualAddress(tableVirtualAddress),
                tableOutputSize,
                tableHasVirtualAddress);
            var plan = new ElfLayoutPlan(
                sourceSha256,
                strategy,
                oldTable,
                newTable,
                sourceHeaders.Length,
                plannedHeaders.Count,
                outputLength,
                ComputePreservedMetadataFingerprint(plannedHeaders),
                programHeaderPlans,
                placements.OrderBy(placement => placement.Identity, StringComparer.Ordinal).ToArray(),
                addressMap.OrderBy(entry => entry.Identity, StringComparer.Ordinal).ToArray(),
                branchDecisions.OrderBy(decision => decision.Identity, StringComparer.Ordinal).ToArray(),
                edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind).ToArray())
            {
                TlsFixups = Array.AsReadOnly(tlsFixupDecisions
                    .OrderBy(decision => decision.OutputVirtualAddress.Value)
                    .ThenBy(decision => decision.OutputFileOffset.Value)
                    .ToArray()),
            };

            if (!ValidateCandidate(
                    sourceFile,
                    sourceLength,
                    options,
                    plan,
                    plannedHeaders,
                    segmentFileStart,
                    segmentVirtualStart,
                    plannedSegment,
                    diagnostics))
            {
                rejected = diagnostics.ToArray();
                return false;
            }

            var score = new CandidateScore(
                isRelocation ? 1 : 0,
                isRelocation ? 1 : 0,
                plan.ProgramHeaders.Count(header => header.EditKind != ElfProgramHeaderEditKind.Unchanged),
                paddingBytes,
                strategy switch
                {
                    ElfLayoutStrategy.ExistingExecutableLoadExtension => 0,
                    ElfLayoutStrategy.AvailableProgramHeaderSlot => 1,
                    _ => 2,
                });
            candidate = new LayoutCandidate(plan, score);
            return true;
        }
        catch (OverflowException)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "ELF layout arithmetic overflowed before materialization.");
            rejected = diagnostics.ToArray();
            return false;
        }
        catch (ArgumentException exception)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, exception.Message);
            rejected = diagnostics.ToArray();
            return false;
        }
    }

    private static bool ValidateCandidate(
        ElfFile sourceFile,
        ulong sourceLength,
        ElfLayoutOptions options,
        ElfLayoutPlan plan,
        IReadOnlyList<ProgramHeader> plannedHeaders,
        ulong segmentFileStart,
        ulong segmentVirtualStart,
        ProgramHeader plannedSegment,
        DiagnosticBag diagnostics)
    {
        if (plan.NewProgramHeaderCount != plannedHeaders.Count
            || plan.NewProgramHeaderTable.Size != checked((ulong)plannedHeaders.Count * sourceFile.Header.ProgramHeaderEntrySize)
            || plan.OutputLength > options.MaximumOutputBytes)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The planned ELF table metadata is inconsistent.");
            return false;
        }

        foreach (var header in plannedHeaders)
        {
            if (!TryAdd(header.Offset, header.FileSize, out var fileEnd)
                || !TryAdd(header.VirtualAddress, header.MemorySize, out _)
                || fileEnd > plan.OutputLength)
            {
                diagnostics.Error(DiagnosticCode.InvalidProgramHeader, "A planned program-header range is not representable within the output.", header.Offset);
                return false;
            }
        }

        var loadHeaders = plannedHeaders
            .Where(header => header.Type == ElfConstants.PtLoad)
            .ToArray();
        var sortedVirtual = loadHeaders.OrderBy(header => header.VirtualAddress).ToArray();
        for (var index = 0; index < sortedVirtual.Length; index++)
        {
            var header = sortedVirtual[index];
            if (header.FileSize > header.MemorySize
                || !IsValidAlignment(header.Alignment, options.MaximumAlignment)
                || (header.Alignment > 1 && header.Offset % header.Alignment != header.VirtualAddress % header.Alignment)
                || !TryAdd(header.Offset, header.FileSize, out var fileEnd)
                || !TryAdd(header.VirtualAddress, header.MemorySize, out var virtualEnd)
                || fileEnd > plan.OutputLength)
            {
                diagnostics.Error(DiagnosticCode.InvalidSegment, "A planned PT_LOAD violates bounded range or alignment invariants.", header.Offset);
                return false;
            }

            if (index > 0)
            {
                var previous = sortedVirtual[index - 1];
                if (!TryAdd(previous.VirtualAddress, previous.MemorySize, out var previousEnd)
                    || previousEnd > header.VirtualAddress)
                {
                    diagnostics.Error(DiagnosticCode.InvalidSegment, "Planned PT_LOAD virtual ranges overlap or are out of order.", header.VirtualAddress);
                    return false;
                }
            }

            _ = virtualEnd;
        }

        var sortedFile = loadHeaders.OrderBy(header => header.Offset).ToArray();
        for (var index = 1; index < sortedFile.Length; index++)
        {
            var previous = sortedFile[index - 1];
            var current = sortedFile[index];
            if (!TryAdd(previous.Offset, previous.FileSize, out var previousEnd)
                || previousEnd > current.Offset)
            {
                diagnostics.Error(DiagnosticCode.InvalidSegment, "Planned PT_LOAD file ranges overlap.", current.Offset);
                return false;
            }
        }

        for (var index = 0; index < sortedFile.Length; index++)
        {
            if (sortedFile[index] != sortedVirtual[index])
            {
                diagnostics.Error(DiagnosticCode.InvalidSegment, "Planned PT_LOAD file and virtual ordering diverges.");
                return false;
            }
        }

        if (plannedSegment.Type != ElfConstants.PtLoad
            || plannedSegment.Flags != GeneratedSegmentPermissions
            || !IsValidAlignment(plannedSegment.Alignment, options.MaximumAlignment)
            || (plannedSegment.Alignment > 1
                && plannedSegment.Offset % plannedSegment.Alignment != plannedSegment.VirtualAddress % plannedSegment.Alignment)
            || (plannedSegment.Offset != segmentFileStart && plan.Strategy != ElfLayoutStrategy.ExistingExecutableLoadExtension
                || plannedSegment.VirtualAddress != segmentVirtualStart && plan.Strategy != ElfLayoutStrategy.ExistingExecutableLoadExtension))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The planned generated segment is not at the selected placement.");
            return false;
        }

        var ownedFileStart = plannedSegment.Offset;
        var ownedVirtualStart = plannedSegment.VirtualAddress;
        var ownedFileSize = plannedSegment.FileSize;
        var ownedVirtualSize = plannedSegment.MemorySize;
        if (plan.Strategy == ElfLayoutStrategy.ExistingExecutableLoadExtension)
        {
            var sourceExtension = plan.ProgramHeaders
                .First(header => header.EditKind == ElfProgramHeaderEditKind.ExtendedExecutableLoad
                    && header.OriginalHeader is ProgramHeader original
                    && original.Type == ElfConstants.PtLoad
                    && original.IsExecutable);
            var originalExtension = sourceExtension.OriginalHeader!.Value;
            if (!TryAdd(originalExtension.Offset, originalExtension.FileSize, out ownedFileStart)
                || !TryAdd(originalExtension.VirtualAddress, originalExtension.FileSize, out ownedVirtualStart)
                || plannedSegment.FileSize < originalExtension.FileSize
                || plannedSegment.MemorySize < originalExtension.MemorySize)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The executable extension ownership range is not representable.");
                return false;
            }

            ownedFileSize = plannedSegment.FileSize - originalExtension.FileSize;
            ownedVirtualSize = plannedSegment.MemorySize - originalExtension.MemorySize;
        }

        foreach (var placement in plan.Placements)
        {
            if (placement.Size == 0
                || placement.Permissions != plannedSegment.Flags
                || !IsValidAlignment(placement.Alignment, options.MaximumAlignment)
                || !TryAdd(placement.FileOffset.Value, placement.Size, out var placementFileEnd)
                || !TryAdd(placement.VirtualAddress.Value, placement.Size, out var placementVirtualEnd)
                || placementFileEnd > plan.OutputLength
                || placement.FileOffset.Value < plannedSegment.Offset
                || placementFileEnd > checked(plannedSegment.Offset + plannedSegment.FileSize)
                || placement.VirtualAddress.Value < plannedSegment.VirtualAddress
                || placementVirtualEnd > checked(plannedSegment.VirtualAddress + plannedSegment.MemorySize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, $"Placement '{placement.Identity}' is outside the generated executable segment.");
                return false;
            }
        }

        foreach (var metadata in plannedHeaders.Where(header => header.Type is not (ElfConstants.PtNull or ElfConstants.PtLoad)))
        {
            if (plan.Strategy == ElfLayoutStrategy.RelocatedProgramHeaderTable
                && metadata.Type == ElfConstants.PtPhdr)
            {
                continue;
            }

            if (metadata.FileSize > 0
                && RangesOverlap(ownedFileStart, ownedFileSize, metadata.Offset, metadata.FileSize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "Generated layout bytes overlap preserved program-header metadata.", metadata.Offset);
                return false;
            }

            if (metadata.MemorySize > 0
                && RangesOverlap(ownedVirtualStart, ownedVirtualSize, metadata.VirtualAddress, metadata.MemorySize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "Generated layout addresses overlap preserved program-header metadata.", metadata.VirtualAddress);
                return false;
            }
        }

        for (var index = 0; index < sourceFile.ProgramHeaders.Count; index++)
        {
            var original = sourceFile.ProgramHeaders[index];
            var planned = plannedHeaders[index];
            var allowedChange = plan.Strategy switch
            {
                ElfLayoutStrategy.ExistingExecutableLoadExtension => index == plan.ProgramHeaders[index].SourceIndex
                    && original.Type == ElfConstants.PtLoad
                    && original.IsExecutable,
                ElfLayoutStrategy.AvailableProgramHeaderSlot => index == plan.ProgramHeaders[index].SourceIndex
                    && original.Type == ElfConstants.PtNull,
                ElfLayoutStrategy.RelocatedProgramHeaderTable => original.Type == ElfConstants.PtPhdr,
                _ => false,
            };
            if (!allowedChange && original != planned)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Program header {index} changed outside the selected layout ownership boundary.",
                    sourceFile.Header.ProgramHeaderOffset);
                return false;
            }
        }

        if (plan.Strategy == ElfLayoutStrategy.RelocatedProgramHeaderTable)
        {
            var tableFileEnd = checked(plan.NewProgramHeaderTable.FileOffset.Value + plan.NewProgramHeaderTable.Size);
            var tableVirtualEnd = checked(plan.NewProgramHeaderTable.VirtualAddress.Value + plan.NewProgramHeaderTable.Size);
            var owningLoad = plannedHeaders.FirstOrDefault(header =>
                header.Type == ElfConstants.PtLoad
                && plan.NewProgramHeaderTable.FileOffset.Value >= header.Offset
                && tableFileEnd <= header.Offset + header.FileSize
                && plan.NewProgramHeaderTable.VirtualAddress.Value >= header.VirtualAddress
                && tableVirtualEnd <= header.VirtualAddress + header.MemorySize);
            if (owningLoad.Type != ElfConstants.PtLoad)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "The relocated program-header table is not mapped by a planned PT_LOAD.");
                return false;
            }
        }

        var phdr = plannedHeaders.FirstOrDefault(header => header.Type == ElfConstants.PtPhdr);
        if (phdr.Type == ElfConstants.PtPhdr)
        {
            if (!TryAdd(phdr.Offset, phdr.FileSize, out var phdrFileEnd)
                || !TryAdd(phdr.VirtualAddress, phdr.MemorySize, out var phdrVirtualEnd)
                || !plannedHeaders.Any(header =>
                    header.Type == ElfConstants.PtLoad
                    && phdr.Offset >= header.Offset
                    && phdrFileEnd <= header.Offset + header.FileSize
                    && phdr.VirtualAddress >= header.VirtualAddress
                    && phdrVirtualEnd <= header.VirtualAddress + header.MemorySize))
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "PT_PHDR is not mapped by a planned PT_LOAD.");
                return false;
            }
        }

        if (sourceFile.Header.SectionHeaderOffset != 0
            && sourceFile.Header.SectionHeaderOffset > plan.OutputLength)
        {
            diagnostics.Error(DiagnosticCode.TableOutOfBounds, "The planned output would not retain the section-header table.");
            return false;
        }

        return ValidateEdits(plan, sourceLength, diagnostics);
    }

    private static bool ValidateEdits(ElfLayoutPlan plan, ulong sourceLength, DiagnosticBag diagnostics)
    {
        ulong previousEnd = 0;
        var first = true;
        foreach (var edit in plan.Edits.OrderBy(edit => edit.Offset.Value).ThenBy(edit => edit.Kind))
        {
            if (edit.Bytes is null || edit.Bytes.Length == 0)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A layout byte edit is empty.");
                return false;
            }

            if (!TryAdd(edit.Offset.Value, checked((ulong)edit.Bytes.Length), out var end)
                || end > plan.OutputLength)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A layout byte edit exceeds the planned output range.", edit.Offset.Value);
                return false;
            }

            if (!first && edit.Offset.Value < previousEnd)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutEditOverlap, "Layout byte edits overlap.", edit.Offset.Value);
                return false;
            }

            if (edit.Offset.Value < sourceLength && end > sourceLength && edit.Kind != ElfLayoutEditKind.Padding)
            {
                diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "A non-padding source edit crosses the source/output boundary.", edit.Offset.Value);
                return false;
            }

            first = false;
            previousEnd = end;
        }

        return true;
    }

    private static void ValidateOptions(ElfLayoutOptions options, DiagnosticBag diagnostics)
    {
        if (options.MaximumOutputBytes == 0
            || options.MaximumOutputBytes > ElfLayoutLimits.DefaultMaximumOutputBytes
            || options.MaximumProgramHeaderCount <= 0
            || options.MaximumProgramHeaderCount > ElfLayoutLimits.DefaultMaximumProgramHeaderCount
            || options.MaximumGeneratedCodeBytes <= 0
            || options.MaximumGeneratedCodeBytes > ElfLayoutLimits.DefaultMaximumGeneratedCodeBytes
            || options.MaximumVeneerCount < 0
            || options.MaximumVeneerCount > ElfLayoutLimits.DefaultMaximumVeneerCount
            || options.MaximumEditCount <= 0
            || options.MaximumEditCount > ElfLayoutLimits.DefaultMaximumEditCount
            || options.MaximumPaddingBytes > options.MaximumOutputBytes
            || options.SegmentAlignment == 0
            || options.CodeAlignment == 0
            || !IsPowerOfTwo(options.SegmentAlignment)
            || !IsPowerOfTwo(options.CodeAlignment)
            || !IsPowerOfTwo(options.MaximumAlignment)
            || options.SegmentAlignment > options.MaximumAlignment
            || options.CodeAlignment > options.MaximumAlignment
            || (options.RequestedStrategy is { } requested && !Enum.IsDefined(requested)))
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutMalformed, "ELF layout options are outside their bounded power-of-two limits.");
        }
    }

    private static void ValidateSource(
        ElfFile sourceFile,
        ulong sourceLength,
        ElfLayoutOptions options,
        DiagnosticBag diagnostics)
    {
        diagnostics.AddRange(ElfValidator.Validate(sourceFile).Diagnostics);
        if (!sourceFile.Header.IsAarch64
            || sourceFile.Header.Type is not (ElfConstants.TypeDyn or ElfConstants.TypeExec)
            || sourceFile.Header.ProgramHeaderEntrySize != ElfConstants.ProgramHeaderSize64
            || sourceFile.Header.ProgramHeaderCount == 0
            || sourceFile.Header.ProgramHeaderCount != sourceFile.ProgramHeaders.Count
            || sourceFile.Header.ProgramHeaderCount > options.MaximumProgramHeaderCount
            || sourceFile.Header.ProgramHeaderCount == ElfConstants.PnXnum)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutUnsupported, "The source ELF is outside the bounded layout planner identity or table contract.");
        }

        if (!TryGetProgramHeaderTableRange(sourceFile, sourceLength, out _, out _))
        {
            diagnostics.Error(DiagnosticCode.TableOutOfBounds, "The source program-header table is outside the source snapshot.");
        }

        foreach (var header in sourceFile.ProgramHeaders)
        {
            if (!TryAdd(header.Offset, header.FileSize, out var fileEnd) || fileEnd > sourceLength)
            {
                diagnostics.Error(DiagnosticCode.TableOutOfBounds, "A source program-header file range is outside the source snapshot.", header.Offset);
            }

            if (!TryAdd(header.VirtualAddress, header.MemorySize, out _))
            {
                diagnostics.Error(DiagnosticCode.AddressOverflow, "A source program-header virtual range overflowed.", header.VirtualAddress);
            }
        }

        ValidateSectionHeaderTable(sourceFile, sourceLength, diagnostics);
    }

    private static void ValidateSectionHeaderTable(
        ElfFile sourceFile,
        ulong sourceLength,
        DiagnosticBag diagnostics)
    {
        var header = sourceFile.Header;
        if (header.SectionHeaderOffset == 0 && header.SectionHeaderCount == 0)
        {
            return;
        }

        ulong tableSize = 0;
        ulong tableEnd = 0;
        var valid = header.SectionHeaderOffset != 0
            && header.SectionHeaderCount != 0
            && header.SectionHeaderEntrySize >= ElfConstants.SectionHeaderSize64
            && TryMultiply(header.SectionHeaderEntrySize, header.SectionHeaderCount, out tableSize)
            && TryAdd(header.SectionHeaderOffset, tableSize, out tableEnd)
            && tableEnd <= sourceLength
            && sourceFile.SectionHeaders.Count == header.SectionHeaderCount;
        if (valid
            && (RangesOverlap(header.SectionHeaderOffset, tableSize, 0, ElfConstants.HeaderSize64)
                || (TryGetProgramHeaderTableRange(sourceFile, sourceLength, out var programTable, out _)
                    && RangesOverlap(header.SectionHeaderOffset, tableSize, programTable.FileOffset.Value, programTable.Size))))
        {
            valid = false;
        }

        if (!valid)
        {
            diagnostics.Error(DiagnosticCode.TableOutOfBounds, "The source section-header table is not fully represented by the layout snapshot.", header.SectionHeaderOffset);
        }
    }

    private static void ValidateTlsFixupRequests(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var seen = new HashSet<(string Region, ulong Offset)>();
        foreach (var request in fixups)
        {
            if (request is null)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLS layout request contains a null fixup.");
                continue;
            }

            var region = regions.FirstOrDefault(candidate => string.Equals(
                candidate.Identity,
                request.RegionIdentity,
                StringComparison.Ordinal));
            var fixup = request.Fixup;
            var type = fixup?.Relocation?.RelocationType;
            var model = fixup?.AccessModel is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                && fixup.Relocation?.Kind == Aarch64RelocationKind.Call26
                ? fixup.AccessModel
                : type is { } relocationType
                    ? TlsRelocationClassifier.GetAccessModel(relocationType)
                    : null;
            if (fixup is null
                || fixup.Relocation is null
                || fixup.AddressExpression is null
                || fixup.Module is null
                || region is null
                || !seen.Add((request.RegionIdentity, request.OutputOffset))
                || model is not (TlsAccessModel.LocalExec or TlsAccessModel.InitialExec or TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic or TlsAccessModel.TlsDesc)
                || (model == TlsAccessModel.LocalExec
                    && (fixup.RelocationFamily != TlsRelocationFamily.Tprel
                        || fixup.AddressExpression.Kind != TlsAddressExpressionKind.ThreadPointerRelative
                        || type is not (ElfConstants.RArm64TlsLeAddTprelHi12
                            or ElfConstants.RArm64TlsLeAddTprelLo12
                            or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                            or ElfConstants.RArm64TlsLeMovwTprelG1
                            or ElfConstants.RArm64TlsLeMovwTprelG0Nc
                            or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)))
                || (model == TlsAccessModel.InitialExec
                    && (fixup.RelocationFamily != TlsRelocationFamily.GotTprel
                        || fixup.AddressExpression.Kind != TlsAddressExpressionKind.ThreadPointerRelative
                        || fixup.GotEntry is null
                        || type is not (ElfConstants.RArm64TlsIeMovwGottprelG1
                            or ElfConstants.RArm64TlsIeMovwGottprelG0Nc
                            or ElfConstants.RArm64TlsIeAdrGottprelPage21
                            or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
                            or ElfConstants.RArm64TlsIeLdGottprelPrel19)))
                || (model == TlsAccessModel.TlsDesc
                    && (fixup.RelocationFamily != TlsRelocationFamily.TlsDesc
                        || fixup.AddressExpression.Kind != TlsAddressExpressionKind.DescriptorMediated
                        || fixup.DescriptorOwner is null
                        || type is not (ElfConstants.RArm64TlsDescAdrPage21
                            or ElfConstants.RArm64TlsDescLd64Lo12
                            or ElfConstants.RArm64TlsDescAddLo12
                            or ElfConstants.RArm64TlsDescCall)))
                || (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                    && (fixup.ModuleOwner is null
                        || (model == TlsAccessModel.GeneralDynamic && fixup.DtpRelOwner is null)
                        || (fixup.Relocation.Kind == Aarch64RelocationKind.Call26
                            ? fixup.PairOrdinal != -1
                            : model == TlsAccessModel.LocalDynamic
                                ? type is not (ElfConstants.RArm64TlsLdAdrPage21
                                    or ElfConstants.RArm64TlsLdAddLo12Nc
                                    or ElfConstants.RArm64TlsLdAddDtprelHi12
                                    or ElfConstants.RArm64TlsLdAddDtprelLo12Nc)
                                : type is not (ElfConstants.RArm64TlsGdAdrPage21
                                    or ElfConstants.RArm64TlsGdAddLo12Nc))))
                || request.OutputOffset > (ulong)region.CodeBytes.Length
                || sizeof(uint) > (ulong)region.CodeBytes.Length - request.OutputOffset
                || (request.OutputOffset & 3) != 0
                || !region.SourceAddress.Value.Equals(fixup.SequenceSourceRange.VirtualAddress.Value)
                || fixup.SequenceSourceRange.Size > region.SourceSize
                || (model is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
                    ? fixup.PairOrdinal is < -1 or > 3
                    : model == TlsAccessModel.TlsDesc
                        ? fixup.PairOrdinal is < 0 or > 3
                        : fixup.PairOrdinal is < 0 or > 1)
                || fixup.RelocationSourceRange.VirtualAddress.Value < region.SourceAddress.Value
                || fixup.RelocationSourceRange.VirtualAddress.Value - region.SourceAddress.Value > region.SourceSize
                || fixup.RelocationSourceRange.Size > region.SourceSize
                    - (fixup.RelocationSourceRange.VirtualAddress.Value - region.SourceAddress.Value))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A TLS fixup has an unsupported model, relocation, output mapping, or source-region ownership.",
                    fixup?.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var fileDelta = fixup.RelocationOutputRange.FileOffset.Value >= fixup.SequenceOutputRange.FileOffset.Value
                ? fixup.RelocationOutputRange.FileOffset.Value - fixup.SequenceOutputRange.FileOffset.Value
                : ulong.MaxValue;
            var virtualDelta = fixup.RelocationOutputRange.VirtualAddress.Value >= fixup.SequenceOutputRange.VirtualAddress.Value
                ? fixup.RelocationOutputRange.VirtualAddress.Value - fixup.SequenceOutputRange.VirtualAddress.Value
                : ulong.MaxValue;
            if (fileDelta != virtualDelta || fileDelta != request.OutputOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec TLS fixup request does not match its semantic source-to-output address map.",
                    fixup.RelocationSourceRange.FileOffset.Value);
            }

            if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                    fixup.RelocationSourceRange.VirtualAddress,
                    sizeof(uint),
                    out var mappedOffset)
                || mappedOffset != fixup.RelocationSourceRange.FileOffset)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A TLS fixup source range disagrees with the structural load map.",
                    fixup.RelocationSourceRange.FileOffset.Value);
            }

            if (model == TlsAccessModel.InitialExec
                && fixup.GotEntry is { } gotEntry
                && !ValidateInitialExecGotEntry(sourceFile, fixup, gotEntry, diagnostics))
            {
                // The helper owns the stable diagnostic; no layout candidate may be built.
            }
        }

        ValidateLocalExecAddRequestPairs(sourceFile, regions, fixups, diagnostics);
        ValidateLocalExecLdst32RequestPairs(sourceFile, fixups, diagnostics);
        ValidateInitialExecMovwRequestPairs(sourceFile, fixups, diagnostics);
        ValidateInitialExecAdrLd64RequestPairs(sourceFile, regions, fixups, diagnostics);
        ValidateInitialExecLdGotPrel19RequestSites(sourceFile, regions, fixups, diagnostics);
        ValidateLocalExecMovwRequestPairs(sourceFile, fixups, diagnostics);
        ValidateTlsDescRequestSequences(sourceFile, regions, fixups, diagnostics);
    }

    private static void ValidateTlsDescRequestSequences(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var groups = fixups
            .Where(request => request?.Fixup?.AccessModel == TlsAccessModel.TlsDesc)
            .GroupBy(request => (request.RegionIdentity, request.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(request => request.Fixup.PairOrdinal).ToArray();
            var region = regions.SingleOrDefault(candidate => string.Equals(
                candidate.Identity,
                group.Key.RegionIdentity,
                StringComparison.Ordinal));
            var valid = region is not null
                && ordered.Length == 4
                && ordered.Select(request => request.Fixup.PairOrdinal).SequenceEqual(TlsDescPairOrdinals)
                && ordered.Select(request => request.Fixup.Relocation.RelocationType).SequenceEqual(TlsDescRelocationTypes)
                && ordered.All(request => request.Fixup.DescriptorOwner is not null)
                && ordered.Zip(ordered.Skip(1)).All(pair =>
                    pair.Second.Fixup.RelocationSourceRange.VirtualAddress.Value
                        == pair.First.Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                    && pair.Second.OutputOffset == pair.First.OutputOffset + sizeof(uint));
            if (valid && region is not null)
            {
                var first = ordered[0].Fixup;
                var sourceOffset = first.RelocationSourceRange.FileOffset.Value;
                var outputOffset = ordered[0].OutputOffset;
                valid = sourceOffset <= (ulong)sourceFile.Bytes.Length
                    && 8 * sizeof(uint) <= (ulong)sourceFile.Bytes.Length - sourceOffset
                    && outputOffset <= (ulong)region.CodeBytes.Length
                    && 8 * sizeof(uint) <= (ulong)region.CodeBytes.Length - outputOffset
                    && TryReadWords(sourceFile.Bytes.Span, sourceOffset, 8 * sizeof(uint), out var sourceWords)
                    && TryReadWords(region.CodeBytes, outputOffset, 8 * sizeof(uint), out var outputWords)
                    && Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
                        sourceWords,
                        first.DescriptorOwner!,
                        first.SequenceSourceRange.VirtualAddress.Value)
                    && Aarch64TlsInstructionSemantics.IsSupportedTlsDescWordSequence(
                        outputWords,
                        first.DescriptorOwner!,
                        first.SequenceOutputRange.VirtualAddress.Value);
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSDESC fixup sequence is incomplete, reordered, or inconsistent with its descriptor owner and output mapping.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
            }
        }
    }


    private static void ValidateLocalExecAddRequestPairs(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var groups = fixups
            .Where(request => request?.Fixup?.Relocation?.RelocationType is
                ElfConstants.RArm64TlsLeAddTprelHi12
                or ElfConstants.RArm64TlsLeAddTprelLo12
                or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
            .GroupBy(request => (request.RegionIdentity, request.Fixup.SequenceSourceRange));

        foreach (var group in groups)
        {
            if (group.Any(request => request.Fixup.Relocation.RelocationType
                    == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
                && group.All(request => request.Fixup.Relocation.RelocationType is
                    ElfConstants.RArm64TlsLeAddTprelHi12
                    or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc))
            {
                continue;
            }

            var ordered = group.OrderBy(request => request.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 2
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[1].Fixup.PairOrdinal == 1
                && ordered[0].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsLeAddTprelHi12
                && ordered[1].Fixup.Relocation.RelocationType is
                    ElfConstants.RArm64TlsLeAddTprelLo12 or ElfConstants.RArm64TlsLeAddTprelLo12Nc
                && ordered[0].Fixup.Relocation.Addend == ordered[1].Fixup.Relocation.Addend
                && ordered[0].Fixup.Relocation.SymbolIndex == ordered[1].Fixup.Relocation.SymbolIndex
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.SequenceOutputRange == ordered[1].Fixup.SequenceOutputRange
                && ordered[0].OutputOffset <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputOffset == ordered[0].OutputOffset + sizeof(uint)
                && ordered[0].Fixup.RelocationSourceRange.FileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    == ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    == ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationOutputRange.FileOffset.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationOutputRange.FileOffset.Value
                    == ordered[0].Fixup.RelocationOutputRange.FileOffset.Value + sizeof(uint)
                && ordered[0].Fixup.RelocationOutputRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationOutputRange.VirtualAddress.Value
                    == ordered[0].Fixup.RelocationOutputRange.VirtualAddress.Value + sizeof(uint);

            var region = valid
                ? regions.SingleOrDefault(candidate => string.Equals(
                    candidate.Identity,
                    group.Key.RegionIdentity,
                    StringComparison.Ordinal))
                : null;
            if (region is null)
            {
                valid = false;
            }

            if (valid && region is not null)
            {
                var first = ordered[0];
                var second = ordered[1];
                var sourceOffset = first.Fixup.RelocationSourceRange.FileOffset.Value;
                var outputOffset = first.OutputOffset;
                valid = sourceOffset >= sizeof(uint)
                    && sourceOffset <= int.MaxValue
                    && sourceOffset <= (ulong)sourceFile.Bytes.Length
                    && sizeof(uint) <= (ulong)sourceFile.Bytes.Length - sourceOffset
                    && outputOffset >= sizeof(uint)
                    && outputOffset <= (ulong)region!.CodeBytes.Length
                    && sizeof(uint) <= (ulong)region!.CodeBytes.Length - outputOffset
                    && outputOffset <= int.MaxValue
                    && outputOffset <= (ulong)region.CodeBytes.Length - sizeof(uint)
                    && sourceOffset <= ulong.MaxValue - (2 * sizeof(uint))
                    && sourceOffset + (2 * sizeof(uint)) <= (ulong)sourceFile.Bytes.Length
                    && outputOffset <= ulong.MaxValue - (2 * sizeof(uint))
                    && outputOffset + (2 * sizeof(uint)) <= (ulong)region.CodeBytes.Length;
                if (valid)
                {
                    var sourceThreadPointer = BinaryPrimitives.ReadUInt32LittleEndian(
                        sourceFile.Bytes.Span.Slice(checked((int)(sourceOffset - sizeof(uint))), sizeof(uint)));
                    var sourceFirst = BinaryPrimitives.ReadUInt32LittleEndian(
                        sourceFile.Bytes.Span.Slice(checked((int)sourceOffset), sizeof(uint)));
                    var sourceSecond = BinaryPrimitives.ReadUInt32LittleEndian(
                        sourceFile.Bytes.Span.Slice(checked((int)(sourceOffset + sizeof(uint))), sizeof(uint)));
                    var sourceAccess = BinaryPrimitives.ReadUInt32LittleEndian(
                        sourceFile.Bytes.Span.Slice(checked((int)(sourceOffset + (2 * sizeof(uint)))), sizeof(uint)));
                    var outputThreadPointer = BinaryPrimitives.ReadUInt32LittleEndian(
                        region!.CodeBytes.AsSpan(checked((int)(outputOffset - sizeof(uint))), sizeof(uint)));
                    var outputFirst = BinaryPrimitives.ReadUInt32LittleEndian(
                        region.CodeBytes.AsSpan(checked((int)outputOffset), sizeof(uint)));
                    var outputSecond = BinaryPrimitives.ReadUInt32LittleEndian(
                        region.CodeBytes.AsSpan(checked((int)(outputOffset + sizeof(uint))), sizeof(uint)));
                    var outputAccess = BinaryPrimitives.ReadUInt32LittleEndian(
                        region.CodeBytes.AsSpan(checked((int)(outputOffset + (2 * sizeof(uint)))), sizeof(uint)));
                    valid = Aarch64TlsInstructionSemantics.IsSupportedLocalExecAddSequence(
                                first.Fixup.Relocation.RelocationType!.Value,
                                sourceFirst,
                                second.Fixup.Relocation.RelocationType!.Value,
                                sourceSecond,
                                sourceThreadPointer,
                                sourceAccess)
                        && Aarch64TlsInstructionSemantics.IsSupportedLocalExecAddSequence(
                            first.Fixup.Relocation.RelocationType!.Value,
                            outputFirst,
                            second.Fixup.Relocation.RelocationType!.Value,
                            outputSecond,
                            outputThreadPointer,
                            outputAccess);
                }
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec ADD TPREL pair is incomplete, interleaved, or inconsistent in identity, TP-relative chain, output mapping, or final TLS access.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
            }
        }
    }

    private static bool ValidateInitialExecGotEntry(
        ElfFile sourceFile,
        TlsSemanticFixup fixup,
        TlsGotEntryBinding gotEntry,
        DiagnosticBag diagnostics)
    {
        var facts = sourceFile.TlsMetadata.StaticRelocations
            .Concat(sourceFile.TlsMetadata.Dynamic.Relocations)
            .Where(fact => fact.Relocation.Type == ElfConstants.RArm64TlsTprel64
                && fact.Relocation.Offset == gotEntry.SourceRange.VirtualAddress.Value
                && fact.Relocation.Addend == gotEntry.Addend
                && fact.Symbol is not null
                && fact.Symbol.SymbolIndex == gotEntry.Symbol.SymbolIndex
                && string.Equals(fact.Symbol.Name, gotEntry.Symbol.Name, StringComparison.Ordinal))
            .ToArray();
        var valid = gotEntry.SourceRange.Size == sizeof(ulong)
            && sourceFile.LoadMap.TryVirtualAddressToFileOffset(
                gotEntry.SourceRange.VirtualAddress,
                sizeof(ulong),
                out var mappedOffset)
            && mappedOffset == gotEntry.SourceRange.FileOffset
            && sourceFile.LoadMap.Segments.Count(segment =>
                segment.ContainsVirtualAddress(gotEntry.SourceRange.VirtualAddress.Value, sizeof(ulong))
                && segment.ContainsFileOffset(gotEntry.SourceRange.FileOffset.Value, sizeof(ulong))
                && (segment.Flags & ElfConstants.PfW) != 0) == 1
            && facts.Length == 1
            && !facts[0].Relocation.IsPlt
            && facts[0].WriteSize == sizeof(ulong)
            && facts[0].Relocation.Info == gotEntry.Relocation.RawInfo
            && facts[0].Relocation.SourceAddress == gotEntry.Relocation.RelocationTableAddress?.Value;
        if (!valid)
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "The TLSIE GOT entry is not uniquely source-owned, writable, mapped, and bound to its R_AARCH64_TLS_TPREL64 relocation.",
                gotEntry.SourceRange.FileOffset.Value);
        }

        return valid;
    }

    private static void ValidateInitialExecAdrLd64RequestPairs(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var groups = fixups
            .Where(request => request?.Fixup?.Relocation?.RelocationType is
                ElfConstants.RArm64TlsIeAdrGottprelPage21
                or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc)
            .GroupBy(request => (request.RegionIdentity, request.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(request => request.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 2
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[1].Fixup.PairOrdinal == 1
                && ordered[0].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeAdrGottprelPage21
                && ordered[1].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeLd64GottprelLo12Nc
                && ordered[0].Fixup.Relocation.Addend == ordered[1].Fixup.Relocation.Addend
                && ordered[0].Fixup.Relocation.SymbolIndex == ordered[1].Fixup.Relocation.SymbolIndex
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.GotEntry == ordered[1].Fixup.GotEntry
                && ordered[0].Fixup.SequenceOutputRange == ordered[1].Fixup.SequenceOutputRange
                && ordered[0].Fixup.RelocationSourceRange.FileOffset.Value >= ordered[0].Fixup.SequenceSourceRange.FileOffset.Value
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value >= ordered[0].Fixup.SequenceSourceRange.VirtualAddress.Value
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    == ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                && ordered[0].OutputOffset <= ulong.MaxValue - sizeof(uint)
                && ordered[1].OutputOffset == ordered[0].OutputOffset + sizeof(uint);
            var region = valid
                ? regions.SingleOrDefault(candidate => string.Equals(
                    candidate.Identity,
                    group.Key.RegionIdentity,
                    StringComparison.Ordinal))
                : null;
            if (region is null)
            {
                valid = false;
            }

            if (valid && region is not null)
            {
                var first = ordered[0].Fixup;
                var sourceDelta = first.RelocationSourceRange.FileOffset.Value
                    - first.SequenceSourceRange.FileOffset.Value;
                var outputDelta = ordered[0].OutputOffset;
                valid = first.SequenceSourceRange.Size >= 2 * sizeof(uint)
                    && sourceDelta % sizeof(uint) == 0
                    && outputDelta % sizeof(uint) == 0
                    && sourceDelta <= first.SequenceSourceRange.Size - (2 * sizeof(uint))
                    && region.CodeBytes.Length >= 2 * sizeof(uint)
                    && outputDelta <= (ulong)region.CodeBytes.Length - (2 * sizeof(uint))
                    && first.SequenceSourceRange.Size <= int.MaxValue
                    && first.SequenceSourceRange.Size % sizeof(uint) == 0
                    && first.SequenceSourceRange.FileOffset.Value <= (ulong)sourceFile.Bytes.Length
                    && first.SequenceSourceRange.Size <= (ulong)sourceFile.Bytes.Length
                        - first.SequenceSourceRange.FileOffset.Value
                    && outputDelta <= (ulong)region.CodeBytes.Length
                    && first.SequenceSourceRange.Size <= (ulong)region.CodeBytes.Length - outputDelta;
                if (valid)
                {
                    var wordCount = checked((int)(first.SequenceSourceRange.Size / sizeof(uint)));
                    var sourceWords = new uint[wordCount];
                    var outputWords = new uint[wordCount];
                    for (var index = 0; index < wordCount; index++)
                    {
                        sourceWords[index] = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                            checked((int)(first.SequenceSourceRange.FileOffset.Value + ((ulong)index * sizeof(uint)))),
                            sizeof(uint)));
                        outputWords[index] = BinaryPrimitives.ReadUInt32LittleEndian(region.CodeBytes.AsSpan(
                            checked((int)(outputDelta + ((ulong)index * sizeof(uint)))),
                            sizeof(uint)));
                    }

                    valid = Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64Sequence(
                                sourceWords,
                                checked((int)(sourceDelta / sizeof(uint))),
                                requireSourceLow12Zero: true)
                        && Aarch64TlsInstructionSemantics.IsSupportedInitialExecAdrLd64Sequence(
                            outputWords,
                            0,
                            requireSourceLow12Zero: false);
                }
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSIE ADRP/LD64 GOTTPREL pair is incomplete, interleaved, or inconsistent in source identity, chain shape, addend, or output mapping.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
            }
        }
    }
    private static void ValidateInitialExecLdGotPrel19RequestSites(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        foreach (var request in fixups.Where(request =>
            request?.Fixup?.Relocation?.RelocationType == ElfConstants.RArm64TlsIeLdGottprelPrel19))
        {
            var fixup = request.Fixup;
            var region = regions.SingleOrDefault(candidate => string.Equals(
                candidate.Identity,
                request.RegionIdentity,
                StringComparison.Ordinal));
            var valid = region is not null
                && region.CodeBytes.Length >= sizeof(uint)
                && fixup.PairOrdinal == 0
                && fixup.GotEntry is { } gotEntry
                && fixup.Relocation.SymbolIndex == gotEntry.Symbol.SymbolIndex
                && string.Equals(fixup.Relocation.SymbolName, gotEntry.Symbol.Name, StringComparison.Ordinal)
                && fixup.Relocation.Addend == gotEntry.Addend
                && fixup.SequenceSourceRange.Size >= 4 * sizeof(uint)
                && fixup.SequenceOutputRange.Size >= 4 * sizeof(uint)
                && fixup.SequenceSourceRange.FileOffset.Value % sizeof(uint) == 0
                && fixup.SequenceSourceRange.VirtualAddress.Value % sizeof(uint) == 0
                && fixup.SequenceOutputRange.FileOffset.Value % sizeof(uint) == 0
                && fixup.SequenceOutputRange.VirtualAddress.Value % sizeof(uint) == 0
                && fixup.RelocationSourceRange.VirtualAddress == fixup.SequenceSourceRange.VirtualAddress
                && fixup.RelocationSourceRange.FileOffset == fixup.SequenceSourceRange.FileOffset
                && request.OutputOffset <= (ulong)region.CodeBytes.Length
                && sizeof(uint) * 4UL <= (ulong)region.CodeBytes.Length - request.OutputOffset
                && fixup.SequenceOutputRange.Size <= (ulong)region.CodeBytes.Length
                && request.OutputOffset <= ulong.MaxValue - (4UL * sizeof(uint))
                && request.OutputOffset + (4UL * sizeof(uint)) <= (ulong)region.CodeBytes.Length
                && fixup.RelocationSourceRange.FileOffset.Value <= int.MaxValue
                && fixup.SequenceSourceRange.FileOffset.Value <= (ulong)sourceFile.Bytes.Length
                && fixup.SequenceSourceRange.Size <= (ulong)sourceFile.Bytes.Length
                    - fixup.SequenceSourceRange.FileOffset.Value
                && Aarch64TlsInstructionSemantics.TryGetInitialExecLdGotPrel19Relocation(
                    fixup.Relocation.RelocationType.GetValueOrDefault(),
                    fixup.RelocationSourceRange.VirtualAddress.Value,
                    fixup.PairOrdinal);
            var sourceRead = false;
            var outputRead = false;
            var sourceChain = false;
            var outputChain = false;
            if (valid)
            {
                sourceRead = TryReadWords(
                    sourceFile.Bytes.Span,
                    fixup.SequenceSourceRange.FileOffset.Value,
                    fixup.SequenceSourceRange.Size,
                    out var sourceWords);
                outputRead = TryReadWords(
                    region!.CodeBytes,
                    0,
                    Math.Max(
                        fixup.SequenceOutputRange.Size,
                        checked(request.OutputOffset + (4UL * sizeof(uint)))),
                    out var outputWords);
                if (sourceRead)
                {
                    sourceChain = Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19Sequence(
                        sourceWords,
                        0,
                        requireZeroSourceImmediate: true);
                }

                if (outputRead && request.OutputOffset / sizeof(uint) <= int.MaxValue)
                {
                    outputChain = Aarch64TlsInstructionSemantics.IsSupportedInitialExecLdGotPrel19Sequence(
                        outputWords,
                        checked((int)(request.OutputOffset / sizeof(uint))));
                }

                valid = sourceChain && outputChain;

            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSIE LD_GOTTPREL_PREL19 fixup is incomplete, not source-mapped at the literal load, or violates its exact literal width/range/TP address chain.",
                    fixup.RelocationSourceRange.FileOffset.Value);
            }
        }
    }

    private static bool TryReadWords(
        ReadOnlySpan<byte> bytes,
        ulong offset,
        ulong size,
        out uint[] words)
    {
        words = Array.Empty<uint>();
        if (size == 0
            || size % sizeof(uint) != 0
            || size > int.MaxValue
            || offset > int.MaxValue
            || offset > (ulong)bytes.Length
            || size > (ulong)bytes.Length - offset)
        {
            return false;
        }

        words = new uint[checked((int)(size / sizeof(uint)))];
        for (var index = 0; index < words.Length; index++)
        {
            words[index] = BinaryPrimitives.ReadUInt32LittleEndian(
                bytes.Slice(checked((int)(offset + ((ulong)index * sizeof(uint)))), sizeof(uint)));
        }

        return true;
    }
    private static void ValidateInitialExecMovwRequestPairs(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var groups = fixups
            .Where(request => request?.Fixup?.Relocation?.RelocationType is
                ElfConstants.RArm64TlsIeMovwGottprelG1 or ElfConstants.RArm64TlsIeMovwGottprelG0Nc)
            .GroupBy(request => (request.RegionIdentity, request.Fixup.SequenceSourceRange));
        foreach (var group in groups)
        {
            var ordered = group.OrderBy(request => request.Fixup.PairOrdinal).ToArray();
            var valid = ordered.Length == 2
                && ordered[0].Fixup.PairOrdinal == 0
                && ordered[1].Fixup.PairOrdinal == 1
                && ordered[0].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG1
                && ordered[1].Fixup.Relocation.RelocationType == ElfConstants.RArm64TlsIeMovwGottprelG0Nc
                && ordered[0].Fixup.Relocation.Addend == ordered[1].Fixup.Relocation.Addend
                && ordered[0].Fixup.Relocation.SymbolIndex == ordered[1].Fixup.Relocation.SymbolIndex
                && string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                && ordered[0].Fixup.GotEntry == ordered[1].Fixup.GotEntry
                && ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value <= ulong.MaxValue - sizeof(uint)
                && ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    == ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                && ordered[1].OutputOffset == ordered[0].OutputOffset + sizeof(uint);
            if (valid)
            {
                var first = ordered[0].Fixup;
                if (first.SequenceSourceRange.Size > int.MaxValue
                    || first.SequenceSourceRange.FileOffset.Value > int.MaxValue
                    || first.SequenceSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                    || first.SequenceSourceRange.Size > (ulong)sourceFile.Bytes.Length - first.SequenceSourceRange.FileOffset.Value
                    || first.RelocationSourceRange.FileOffset.Value < first.SequenceSourceRange.FileOffset.Value)
                {
                    valid = false;
                }
                else
                {
                    var wordCount = checked((int)(first.SequenceSourceRange.Size / sizeof(uint)));
                    var words = new uint[wordCount];
                    for (var index = 0; index < wordCount; index++)
                    {
                        words[index] = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                            checked((int)(first.SequenceSourceRange.FileOffset.Value + ((ulong)index * sizeof(uint)))),
                            sizeof(uint)));
                    }

                    var pairDelta = first.RelocationSourceRange.FileOffset.Value - first.SequenceSourceRange.FileOffset.Value;
                    valid = pairDelta % sizeof(uint) == 0
                        && Aarch64TlsInstructionSemantics.IsSupportedInitialExecMovwSequence(
                            words,
                            checked((int)(pairDelta / sizeof(uint))));
                }
            }

            if (!valid)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSIE MOVW GOTTPREL pair is incomplete, interleaved, or inconsistent in source identity, chain shape, addend, or output mapping.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
            }
        }
    }

    private static void ValidateLocalExecLdst32RequestPairs(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var ldstGroups = fixups
            .Where(request => request?.Fixup?.Relocation?.RelocationType
                == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
            .GroupBy(request => (request.RegionIdentity, request.Fixup.SequenceSourceRange));

        foreach (var ldstGroup in ldstGroups)
        {
            var ordered = fixups
                .Where(request => request is not null
                    && string.Equals(request.RegionIdentity, ldstGroup.Key.RegionIdentity, StringComparison.Ordinal)
                    && request.Fixup.SequenceSourceRange == ldstGroup.Key.SequenceSourceRange
                    && request.Fixup.Relocation.RelocationType is
                        ElfConstants.RArm64TlsLeAddTprelHi12 or ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
                .OrderBy(request => request.Fixup.PairOrdinal)
                .ToArray();

            if (ordered.Length != 2
                || ordered[0].Fixup.PairOrdinal != 0
                || ordered[1].Fixup.PairOrdinal != 1
                || ordered[0].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeAddTprelHi12
                || ordered[1].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeLdst32TprelLo12Nc
                || ordered[0].Fixup.Relocation.Addend != ordered[1].Fixup.Relocation.Addend
                || ordered[0].Fixup.Relocation.SymbolIndex != ordered[1].Fixup.Relocation.SymbolIndex
                || !string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                || ordered[0].Fixup.Symbol is null
                || ordered[1].Fixup.Symbol != ordered[0].Fixup.Symbol
                || ordered[1].Fixup.Module != ordered[0].Fixup.Module
                || ordered[0].OutputOffset > ulong.MaxValue - sizeof(uint)
                || ordered[1].OutputOffset != ordered[0].OutputOffset + sizeof(uint)
                || ordered[0].Fixup.RelocationSourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    != ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    != ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                || ordered[0].Fixup.RelocationOutputRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].Fixup.RelocationOutputRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].Fixup.RelocationOutputRange.FileOffset.Value
                    != ordered[0].Fixup.RelocationOutputRange.FileOffset.Value + sizeof(uint)
                || ordered[1].Fixup.RelocationOutputRange.VirtualAddress.Value
                    != ordered[0].Fixup.RelocationOutputRange.VirtualAddress.Value + sizeof(uint))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec LDST32 TLS fixup pair is incomplete, interleaved, or inconsistent in identity, addend, order, or mapped output ranges.",
                    ordered.Length == 0 ? null : ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var first = ordered[0].Fixup;
            var second = ordered[1].Fixup;
            if (first.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || second.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || first.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - first.RelocationSourceRange.FileOffset.Value
                || second.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - second.RelocationSourceRange.FileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec LDST32 TLS fixup pair is outside the bounded source image.",
                    first.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var firstEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)first.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            var secondEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)second.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            if (first.Symbol is null
                || !Aarch64TlsInstructionSemantics.TryAddSigned(
                    first.Symbol.Value,
                    first.Addend,
                    out var tprelOffset)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                    first.Relocation.RelocationType!.Value,
                    firstEncoding,
                    first.RelocationSourceRange.VirtualAddress.Value,
                    first.Relocation.Addend,
                    second.Relocation.RelocationType!.Value,
                    secondEncoding,
                    second.RelocationSourceRange.VirtualAddress.Value,
                    second.Relocation.Addend,
                    tprelOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec LDST32 TLS fixup pair does not match the ABI width, scale, opcode, register, TP-relative offset, order, or addend contract.",
                    first.RelocationSourceRange.FileOffset.Value);
            }
        }
    }

    private static void ValidateLocalExecMovwRequestPairs(
        ElfFile sourceFile,
        IReadOnlyList<ElfLayoutTlsFixupRequest> fixups,
        DiagnosticBag diagnostics)
    {
        var movwRequests = fixups
            .Where(request => request?.Fixup?.Relocation?.RelocationType is { } type
                && type is ElfConstants.RArm64TlsLeMovwTprelG1 or ElfConstants.RArm64TlsLeMovwTprelG0Nc)
            .GroupBy(request => (request.RegionIdentity, request.Fixup.SequenceSourceRange));

        foreach (var group in movwRequests)
        {
            var ordered = group.OrderBy(request => request.Fixup.PairOrdinal).ToArray();
            if (ordered.Length != 2
                || ordered[0].Fixup.PairOrdinal != 0
                || ordered[1].Fixup.PairOrdinal != 1
                || ordered[0].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeMovwTprelG1
                || ordered[1].Fixup.Relocation.RelocationType != ElfConstants.RArm64TlsLeMovwTprelG0Nc
                || ordered[0].Fixup.Relocation.Addend != ordered[1].Fixup.Relocation.Addend
                || ordered[0].Fixup.Relocation.SymbolIndex != ordered[1].Fixup.Relocation.SymbolIndex
                || !string.Equals(
                    ordered[0].Fixup.Relocation.SymbolName,
                    ordered[1].Fixup.Relocation.SymbolName,
                    StringComparison.Ordinal)
                || ordered[0].Fixup.SequenceOutputRange != ordered[1].Fixup.SequenceOutputRange
                || ordered[0].Fixup.RelocationSourceRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.FileOffset.Value
                    != ordered[0].Fixup.RelocationSourceRange.FileOffset.Value + sizeof(uint)
                || ordered[1].Fixup.RelocationSourceRange.VirtualAddress.Value
                    != ordered[0].Fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint)
                || ordered[0].OutputOffset > ulong.MaxValue - sizeof(uint)
                || ordered[1].OutputOffset != ordered[0].OutputOffset + sizeof(uint)
                || ordered[0].Fixup.RelocationOutputRange.FileOffset.Value > ulong.MaxValue - sizeof(uint)
                || ordered[0].Fixup.RelocationOutputRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint)
                || ordered[1].Fixup.RelocationOutputRange.FileOffset.Value
                    != ordered[0].Fixup.RelocationOutputRange.FileOffset.Value + sizeof(uint)
                || ordered[1].Fixup.RelocationOutputRange.VirtualAddress.Value
                    != ordered[0].Fixup.RelocationOutputRange.VirtualAddress.Value + sizeof(uint))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec MOVW TLS fixup pair is incomplete, interleaved, or inconsistent in identity, addend, or output mapping.",
                    ordered[0].Fixup.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var first = ordered[0].Fixup;
            var second = ordered[1].Fixup;
            if (first.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || second.RelocationSourceRange.FileOffset.Value > int.MaxValue
                || first.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - first.RelocationSourceRange.FileOffset.Value
                || second.RelocationSourceRange.FileOffset.Value > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - second.RelocationSourceRange.FileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "A local-exec MOVW TLS fixup pair is outside the bounded source image.",
                    first.RelocationSourceRange.FileOffset.Value);
                continue;
            }

            var firstEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)first.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            var secondEncoding = BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                checked((int)second.RelocationSourceRange.FileOffset.Value), sizeof(uint)));
            if (!Aarch64TlsInstructionSemantics.IsSupportedLocalExecMovwPair(
                    first.Relocation.RelocationType!.Value,
                    firstEncoding,
                    first.RelocationSourceRange.VirtualAddress.Value,
                    first.Relocation.Addend,
                    second.Relocation.RelocationType!.Value,
                    secondEncoding,
                    second.RelocationSourceRange.VirtualAddress.Value,
                    second.Relocation.Addend))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec MOVW TLS fixup pair does not match the ABI opcode, shift, destination-register, order, or addend contract.",
                    first.RelocationSourceRange.FileOffset.Value);
            }
        }
    }

    private static bool IsLocalExecLdst32HiRelocation(ElfFile sourceFile, TlsSemanticFixup fixup)
    {
        if (fixup.RelocationSourceRange.VirtualAddress.Value > ulong.MaxValue - sizeof(uint))
        {
            return false;
        }

        var nextAddress = fixup.RelocationSourceRange.VirtualAddress.Value + sizeof(uint);
        var nextRelocations = sourceFile.TlsMetadata.StaticRelocations
            .Concat(sourceFile.TlsMetadata.Dynamic.Relocations)
            .Where(fact => fact.Relocation.Offset == nextAddress
                && fact.Relocation.Type == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc
                && fact.Relocation.SymbolIndex == fixup.Relocation.SymbolIndex
                && fact.Relocation.Addend == fixup.Relocation.Addend
                && string.Equals(fact.Symbol?.Name, fixup.Relocation.SymbolName, StringComparison.Ordinal))
            .Take(2)
            .ToArray();
        return nextRelocations.Length == 1;
    }

    private static bool ApplyTlsFixup(
        ElfFile sourceFile,
        ElfLayoutRegionRequest region,
        ElfLayoutPlacement placement,
        ElfLayoutTlsFixupRequest request,
        byte[] outputCode,
        List<ElfLayoutTlsFixupDecision> decisions,
        DiagnosticBag diagnostics)
    {
        var fixup = request.Fixup;
        var relocationType = fixup.Relocation.RelocationType!.Value;
        var sourceOffset = fixup.RelocationSourceRange.FileOffset.Value;
        if (sourceOffset > int.MaxValue
            || sourceOffset > (ulong)sourceFile.Bytes.Length
            || sizeof(uint) > (ulong)sourceFile.Bytes.Length - sourceOffset)
        {
            diagnostics.Error(
                DiagnosticCode.TlsMetadataMalformed,
                "The local-exec TLS relocation instruction is outside the bounded source image.",
                sourceOffset);
            return false;
        }

        var sourceEncoding = BinaryPrimitives.ReadUInt32LittleEndian(
            sourceFile.Bytes.Span.Slice(checked((int)sourceOffset), sizeof(uint)));
        var outputIndex = checked((int)request.OutputOffset);
        var outputEncoding = BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(outputIndex, sizeof(uint)));
        uint fixedEncoding;
        if (fixup.AccessModel is TlsAccessModel.LocalDynamic or TlsAccessModel.GeneralDynamic
            && fixup.Relocation.Kind == Aarch64RelocationKind.Call26)
        {
            if (fixup.ResolverCall is null
                || fixup.ModuleOwner is null
                || !TryAdd(placement.VirtualAddress.Value, (ulong)outputIndex, out var outputAddress)
                || !Aarch64TlsInstructionSemantics.TryEncodeLocalDynamicResolverCall(
                    sourceEncoding,
                    outputEncoding,
                    fixup.RelocationSourceRange.VirtualAddress.Value,
                    outputAddress,
                    out fixedEncoding))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLS dynamic resolver CALL26 conflicts with its source target, output range, or direct-call encoding contract.",
                    sourceOffset);
                return false;
            }
        }
        else if (fixup.AccessModel == TlsAccessModel.TlsDesc
            && relocationType is ElfConstants.RArm64TlsDescAdrPage21
                or ElfConstants.RArm64TlsDescLd64Lo12
                or ElfConstants.RArm64TlsDescAddLo12
                or ElfConstants.RArm64TlsDescCall)
        {
            if (fixup.DescriptorOwner is null
                || !TryAdd(placement.VirtualAddress.Value, (ulong)outputIndex, out var tlsDescOutputAddress)
                || !Aarch64TlsInstructionSemantics.TryEncodeTlsDescInstruction(
                    relocationType,
                    sourceEncoding,
                    outputEncoding,
                    fixup.RelocationSourceRange.VirtualAddress.Value,
                    tlsDescOutputAddress,
                    fixup.DescriptorOwner,
                    out fixedEncoding))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSDESC output instruction conflicts with its descriptor owner, marker family, operand shape, or output mapping.",
                    sourceOffset);
                return false;
            }
        }
        else if (relocationType is ElfConstants.RArm64TlsLdAdrPage21
            or ElfConstants.RArm64TlsLdAddLo12Nc
            or ElfConstants.RArm64TlsGdAdrPage21
            or ElfConstants.RArm64TlsGdAddLo12Nc)
        {
            var isAdr = relocationType is ElfConstants.RArm64TlsLdAdrPage21 or ElfConstants.RArm64TlsGdAdrPage21;
            var pairSourceOffset = isAdr ? sourceOffset : sourceOffset >= sizeof(uint) ? sourceOffset - sizeof(uint) : ulong.MaxValue;
            var pairOutputOffset = isAdr ? (ulong)outputIndex : (ulong)outputIndex >= sizeof(uint) ? (ulong)outputIndex - sizeof(uint) : ulong.MaxValue;
            var pairSourceAddress = isAdr
                ? fixup.RelocationSourceRange.VirtualAddress.Value
                : fixup.RelocationSourceRange.VirtualAddress.Value >= sizeof(uint)
                    ? fixup.RelocationSourceRange.VirtualAddress.Value - sizeof(uint)
                    : ulong.MaxValue;
            if (fixup.ModuleOwner is null
                || pairSourceOffset == ulong.MaxValue
                || pairSourceAddress == ulong.MaxValue
                || pairOutputOffset == ulong.MaxValue
                || pairSourceOffset > int.MaxValue
                || pairSourceOffset > (ulong)sourceFile.Bytes.Length
                || 2 * sizeof(uint) > (ulong)sourceFile.Bytes.Length - pairSourceOffset
                || pairOutputOffset > (ulong)outputCode.Length
                || 2 * sizeof(uint) > (ulong)outputCode.Length - pairOutputOffset
                || !TryAdd(placement.VirtualAddress.Value, pairOutputOffset, out var pairOutputAddress)
                || !Aarch64TlsInstructionSemantics.TryEncodeLocalDynamicModulePair(
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(checked((int)pairSourceOffset), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(checked((int)(pairSourceOffset + sizeof(uint))), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(checked((int)pairOutputOffset), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(checked((int)(pairOutputOffset + sizeof(uint))), sizeof(uint))),
                    relocationType == ElfConstants.RArm64TlsGdAdrPage21 || relocationType == ElfConstants.RArm64TlsGdAddLo12Nc
                        ? ElfConstants.RArm64TlsGdAddLo12Nc
                        : ElfConstants.RArm64TlsLdAddLo12Nc,
                    pairSourceAddress,
                    pairOutputAddress,
                    fixup.ModuleOwner.SourceRange.VirtualAddress.Value,
                    fixup.Addend,
                    out var encodedAdr,
                    out var encodedAdd))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLS dynamic module-ID ADRP/ADD output pair conflicts with its loader-owned DTPMOD64 slot or page/low-12 encoding.",
                    sourceOffset);
                return false;
            }

            fixedEncoding = isAdr ? encodedAdr : encodedAdd;
        }
        else if (fixup.AccessModel == TlsAccessModel.LocalDynamic
            && relocationType is ElfConstants.RArm64TlsLdAddDtprelHi12 or ElfConstants.RArm64TlsLdAddDtprelLo12Nc)
        {
            if (!TryAdd(placement.VirtualAddress.Value, (ulong)outputIndex, out var dtpRelOutputAddress)
                || !Aarch64TlsInstructionSemantics.TryEncodeLocalDynamicDtprel(
                    relocationType,
                    sourceEncoding,
                    outputEncoding,
                    fixup.RelocationSourceRange.VirtualAddress.Value,
                    dtpRelOutputAddress,
                    out fixedEncoding))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSLD DTPREL output instruction conflicts with its typed ADD immediate or register contract.",
                    sourceOffset);
                return false;
            }
        }
        else
        if (relocationType == ElfConstants.RArm64TlsIeLdGottprelPrel19)
        {
            if (fixup.GotEntry is null
                || !TryAdd(placement.VirtualAddress.Value, (ulong)outputIndex, out var outputAddress)
                || !Aarch64TlsInstructionSemantics.TryEncodeInitialExecLdGotPrel19(
                    sourceEncoding,
                    outputEncoding,
                    outputAddress,
                    fixup.GotEntry.SourceRange.VirtualAddress.Value,
                    fixup.Addend,
                    out fixedEncoding))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSIE LD_GOTTPREL_PREL19 output literal conflicts with its GOT owner, signed range, width, or output mapping.",
                    sourceOffset);
                return false;
            }
        }
        else if (relocationType is ElfConstants.RArm64TlsIeAdrGottprelPage21
            or ElfConstants.RArm64TlsIeLd64GottprelLo12Nc)
        {
            var isAdr = relocationType == ElfConstants.RArm64TlsIeAdrGottprelPage21;
            var pairSourceOffset = isAdr
                ? sourceOffset
                : sourceOffset >= sizeof(uint) ? sourceOffset - sizeof(uint) : ulong.MaxValue;
            var pairOutputOffset = isAdr
                ? (ulong)outputIndex
                : (ulong)outputIndex >= sizeof(uint) ? (ulong)outputIndex - sizeof(uint) : ulong.MaxValue;
            if (fixup.GotEntry is null
                || pairSourceOffset == ulong.MaxValue
                || pairOutputOffset == ulong.MaxValue
                || pairSourceOffset > int.MaxValue
                || pairSourceOffset > (ulong)sourceFile.Bytes.Length
                || 2 * sizeof(uint) > (ulong)sourceFile.Bytes.Length - pairSourceOffset
                || pairOutputOffset > (ulong)outputCode.Length
                || 2 * sizeof(uint) > (ulong)outputCode.Length - pairOutputOffset
                || !Aarch64TlsInstructionSemantics.TryEncodeInitialExecAdrLd64Pair(
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)pairSourceOffset), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)(pairSourceOffset + sizeof(uint))), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(
                        checked((int)pairOutputOffset), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(
                        checked((int)(pairOutputOffset + sizeof(uint))), sizeof(uint))),
                    placement.VirtualAddress.Value + pairOutputOffset,
                    fixup.GotEntry?.SourceRange.VirtualAddress.Value ?? 0,
                    fixup.Addend,
                    out var encodedAdr,
                    out var encodedLd))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSIE ADRP/LD64 output pair conflicts with its page, scaled low-12, GOT, opcode, or register contract.",
                    sourceOffset);
                return false;
            }

            fixedEncoding = isAdr ? encodedAdr : encodedLd;
        }
        else if (relocationType is ElfConstants.RArm64TlsIeMovwGottprelG1 or ElfConstants.RArm64TlsIeMovwGottprelG0Nc)
        {
            const uint relocationMask = 0x001F_FFE0u;
            if (!Aarch64TlsInstructionSemantics.IsSupportedInitialExecRelocationInstruction(relocationType, sourceEncoding)
                || !Aarch64TlsInstructionSemantics.IsSupportedInitialExecRelocationInstruction(relocationType, outputEncoding)
                || (sourceEncoding & 0xFFE0_0000u) != (outputEncoding & 0xFFE0_0000u))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The TLSIE output instruction conflicts with its MOVW GOTTPREL opcode, width, or shift contract.",
                    sourceOffset);
                return false;
            }

            fixedEncoding = (outputEncoding & ~relocationMask) | (sourceEncoding & relocationMask);
        }
        else if (relocationType == ElfConstants.RArm64TlsLeAddTprelHi12
            && IsLocalExecLdst32HiRelocation(sourceFile, fixup))
        {
            const uint relocationMask = 0x003F_FC00u;
            var sourceNextOffset = checked(sourceOffset + sizeof(uint));
            var outputNextOffset = checked((ulong)outputIndex + sizeof(uint));
            if (sourceOffset < sizeof(uint)
                || outputIndex < sizeof(uint)
                || sourceNextOffset > (ulong)sourceFile.Bytes.Length
                || sizeof(uint) > (ulong)sourceFile.Bytes.Length - sourceNextOffset
                || outputNextOffset > (ulong)outputCode.Length
                || sizeof(uint) > (ulong)outputCode.Length - outputNextOffset
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Sequence(
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)(sourceOffset - sizeof(uint))), sizeof(uint))),
                    sourceEncoding,
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)sourceNextOffset), sizeof(uint))))
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Sequence(
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(outputIndex - sizeof(uint), sizeof(uint))),
                    outputEncoding,
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(checked((int)outputNextOffset), sizeof(uint)))))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec ADD HI12/LDST32 output chain conflicts with its typed opcode, scaled-immediate, register, or TP-relative semantics.",
                    sourceOffset);
                return false;
            }

            fixedEncoding = (outputEncoding & ~relocationMask) | (sourceEncoding & relocationMask);
        }
        else if (relocationType is ElfConstants.RArm64TlsLeAddTprelHi12
            or ElfConstants.RArm64TlsLeAddTprelLo12
            or ElfConstants.RArm64TlsLeAddTprelLo12Nc)
        {
            var relocationMask = 0x003F_FC00u;
            if (!Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(relocationType, sourceEncoding)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(relocationType, outputEncoding)
                || ((outputEncoding & ~relocationMask) != (sourceEncoding & ~relocationMask)))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec TLS output instruction conflicts with its typed ADD TPREL relocation or register mapping.",
                    sourceOffset);
                return false;
            }

            // The linker-resolved ADD immediate is placement-independent. Copy only
            // its typed relocation field; never infer a TPREL value from ELF layout.
            fixedEncoding = (outputEncoding & ~relocationMask) | (sourceEncoding & relocationMask);
        }
        else if (relocationType == ElfConstants.RArm64TlsLeLdst32TprelLo12Nc)
        {
            const uint relocationMask = 0x003F_FC00u;
            if (!Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(relocationType, sourceEncoding)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(relocationType, outputEncoding)
                || (sourceEncoding & 0x3FC0_0000u) != (outputEncoding & 0x3FC0_0000u)
                || sourceOffset < 2 * sizeof(uint)
                || (ulong)outputIndex < 2 * sizeof(uint)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Sequence(
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)(sourceOffset - (2 * sizeof(uint)))), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)(sourceOffset - sizeof(uint))), sizeof(uint))),
                    sourceEncoding)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Sequence(
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(outputIndex - (2 * sizeof(uint)), sizeof(uint))),
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(outputIndex - sizeof(uint), sizeof(uint))),
                    outputEncoding)
                || fixup.Symbol is null
                || !Aarch64TlsInstructionSemantics.TryAddSigned(
                    fixup.Symbol.Value,
                    fixup.Addend,
                    out var tprelOffset)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                    ElfConstants.RArm64TlsLeAddTprelHi12,
                    BinaryPrimitives.ReadUInt32LittleEndian(sourceFile.Bytes.Span.Slice(
                        checked((int)(sourceOffset - sizeof(uint))), sizeof(uint))),
                    fixup.RelocationSourceRange.VirtualAddress.Value - sizeof(uint),
                    fixup.Relocation.Addend,
                    relocationType,
                    sourceEncoding,
                    fixup.RelocationSourceRange.VirtualAddress.Value,
                    fixup.Relocation.Addend,
                    tprelOffset)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecLdst32Pair(
                    ElfConstants.RArm64TlsLeAddTprelHi12,
                    BinaryPrimitives.ReadUInt32LittleEndian(outputCode.AsSpan(outputIndex - sizeof(uint), sizeof(uint))),
                    checked(placement.VirtualAddress.Value + request.OutputOffset - sizeof(uint)),
                    fixup.Relocation.Addend,
                    relocationType,
                    outputEncoding,
                    checked(placement.VirtualAddress.Value + request.OutputOffset),
                    fixup.Relocation.Addend,
                    tprelOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec LDST32 output instruction conflicts with its typed width, scale, opcode, register, pair, or addend contract.",
                    sourceOffset);
                return false;
            }

            // Preserve the linker-resolved byte offset; the emitted code owns the
            // rewritten base/value registers and the verified LDR/STR opcode.
            fixedEncoding = (outputEncoding & ~relocationMask) | (sourceEncoding & relocationMask);
        }
        else if (relocationType is ElfConstants.RArm64TlsLeMovwTprelG1 or ElfConstants.RArm64TlsLeMovwTprelG0Nc)
        {
            const uint relocationMask = 0x001F_FFE0;
            if (!Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(relocationType, sourceEncoding)
                || !Aarch64TlsInstructionSemantics.IsSupportedLocalExecRelocationInstruction(relocationType, outputEncoding)
                || (sourceEncoding & 0xFFE0_0000u) != (outputEncoding & 0xFFE0_0000u))
            {
                diagnostics.Error(
                    DiagnosticCode.TlsLayoutMismatch,
                    "The local-exec TLS output instruction conflicts with its typed MOVW TPREL opcode or shift.",
                    sourceOffset);
                return false;
            }

            // Preserve the already resolved linker immediate while leaving the
            // register-permuted destination and opcode owned by the emitted code.
            fixedEncoding = (outputEncoding & ~relocationMask) | (sourceEncoding & relocationMask);
        }
        else
        {
            diagnostics.Error(
                DiagnosticCode.TlsSemanticsUnsupported,
                "The local-exec TLS output fixup uses an unsupported relocation form.",
                sourceOffset);
            return false;
        }
        BinaryPrimitives.WriteUInt32LittleEndian(outputCode.AsSpan(outputIndex, sizeof(uint)), fixedEncoding);
        if (!TryAdd(placement.FileOffset.Value, request.OutputOffset, out var outputFileOffset)
            || !TryAdd(placement.VirtualAddress.Value, request.OutputOffset, out var outputVirtualAddress))
        {
            diagnostics.Error(
                DiagnosticCode.TlsLayoutMismatch,
                "The local-exec TLS output relocation address overflows its planned placement.",
                sourceOffset);
            return false;
        }

        decisions.Add(new ElfLayoutTlsFixupDecision(
            region.Identity,
            fixup,
            new FileOffset(outputFileOffset),
            new VirtualAddress(outputVirtualAddress),
            fixedEncoding));
        return true;
    }

    private static void ValidateRequests(
        ElfFile sourceFile,
        ulong sourceLength,
        IReadOnlyList<ElfLayoutRegionRequest> regions,
        IReadOnlyList<ElfLayoutBranchRequest> branches,
        ElfLayoutOptions options,
        DiagnosticBag diagnostics)
    {
        if (regions.Count == 0
            || regions.Count > options.MaximumEditCount
            || branches.Count > options.MaximumEditCount - regions.Count)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutOutputLimitExceeded, "The layout request count is outside its configured bound.");
            return;
        }

        var identities = new HashSet<string>(StringComparer.Ordinal);
        var sourceRanges = new List<(ulong Offset, ulong Size, string Identity)>(regions.Count);
        foreach (var region in regions)
        {
            if (!IsValidIdentity(region.Identity)
                || !IsValidIdentity(region.SourceIdentity)
                || !identities.Add(region.Identity)
                || region.SourceSize < sizeof(uint)
                || (region.SourceSize & 3) != 0
                || (region.SourceAddress.Value & 3) != 0
                || region.CodeBytes.Length == 0
                || region.CodeBytes.Length > options.MaximumGeneratedCodeBytes
                || (region.CodeBytes.Length & 3) != 0
                || !IsPowerOfTwo(region.Alignment)
                || region.Alignment > options.MaximumAlignment
                || region.Permissions != GeneratedSegmentPermissions
                || !TryAdd(region.SourceAddress.Value, region.SourceSize, out _)
                || sourceFile.LoadMap.Segments.Count(segment =>
                    segment.IsExecutable && segment.ContainsVirtualAddress(region.SourceAddress.Value, region.SourceSize)) != 1)
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout region '{region.Identity}' is outside the bounded executable source contract.",
                    region.SourceAddress.Value);
                continue;
            }

            if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(region.SourceAddress, region.SourceSize, out var fileOffset)
                || fileOffset.Value > sourceLength
                || region.SourceSize > sourceLength - fileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.AddressUnmapped,
                    $"Layout region '{region.Identity}' is not file-backed by its executable PT_LOAD.",
                    region.SourceAddress.Value);
            }
            else if (IntersectsProtectedSourceMetadata(sourceFile, fileOffset.Value, region.SourceSize))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout region '{region.Identity}' overlaps an ELF header or preserved program-header metadata.",
                    fileOffset.Value);
            }
            else if (sourceRanges.Any(existing => RangesOverlap(existing.Offset, existing.Size, fileOffset.Value, region.SourceSize)))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout region '{region.Identity}' overlaps another transformed source range.",
                    fileOffset.Value);
            }
            else
            {
                sourceRanges.Add((fileOffset.Value, region.SourceSize, region.Identity));
            }
        }

        var branchIdentities = new HashSet<string>(StringComparer.Ordinal);
        var sourceSites = new HashSet<(string Identity, uint Offset)>();
        foreach (var branch in branches)
        {
            var sourceRegion = regions.FirstOrDefault(region => string.Equals(region.Identity, branch.SourceIdentity, StringComparison.Ordinal));
            var targetRegion = regions.FirstOrDefault(region => string.Equals(region.Identity, branch.TargetIdentity, StringComparison.Ordinal));
            if (!IsValidIdentity(branch.Identity)
                || !branchIdentities.Add(branch.Identity)
                || sourceRegion is null
                || targetRegion is null
                || branch.SourceAddress != sourceRegion.SourceAddress
                || !sourceSites.Add((branch.SourceIdentity, branch.SourceOffset))
                || branch.Encoding != ElfLayoutBranchEncodingKind.Branch26
                || (branch.SourceAddress.Value & 3) != 0
                || (branch.SourceOffset & 3) != 0
                || branch.SourceOffset > sourceRegion.SourceSize
                || sourceRegion.SourceSize - branch.SourceOffset < sizeof(uint)
                || (branch.TargetOffset & 3) != 0
                || branch.TargetOffset > (uint)targetRegion.CodeBytes.Length
                || targetRegion.CodeBytes.Length - branch.TargetOffset < sizeof(uint)
                || !IsBranchOpcode(branch.Opcode))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' is outside the bounded Branch26 contract.",
                    branch.SourceAddress.Value);
                continue;
            }

            if (branch.NearVeneer is not null
                && (!IsValidIdentity(branch.NearVeneer.Identity)
                    || !IsValidIdentity(branch.NearVeneer.TargetIdentity)
                    || !IsPowerOfTwo(branch.NearVeneer.Alignment)
                    || branch.NearVeneer.Alignment > options.MaximumAlignment
                    || branch.NearVeneer.CodeBytes.Length == 0
                    || (branch.NearVeneer.CodeBytes.Length & 3) != 0
                    || branch.NearVeneer.Permissions != GeneratedSegmentPermissions))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' has an invalid veneer request.",
                    branch.SourceAddress.Value);
            }

            if (branch.LongBranch is not null
                && (!IsValidIdentity(branch.LongBranch.Identity)
                    || !IsPowerOfTwo(branch.LongBranch.Alignment)
                    || branch.LongBranch.Alignment > options.MaximumAlignment
                    || branch.LongBranch.CodeBytes.Length == 0
                    || (branch.LongBranch.CodeBytes.Length & 3) != 0
                    || branch.LongBranch.Permissions != GeneratedSegmentPermissions
                    || branch.LongBranch.SourceReplacementBytes is null))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' has an invalid long-address request.",
                    branch.SourceAddress.Value);
            }
            else if (branch.LongBranch?.SourceReplacementBytes is { } replacement
                && (replacement.Length < sizeof(uint)
                    || (replacement.Length & 3) != 0
                    || (ulong)replacement.Length > sourceRegion!.SourceSize - branch.SourceOffset))
            {
                diagnostics.Error(
                    DiagnosticCode.ElfLayoutMalformed,
                    $"Layout branch '{branch.Identity}' has a long-address source replacement outside its source region.",
                    branch.SourceAddress.Value);
            }
        }
    }

    private static bool TryGetAlignedPlacement(
        ElfFile sourceFile,
        ulong sourceLength,
        ElfLayoutOptions options,
        out ulong fileOffset,
        out ulong virtualAddress,
        DiagnosticBag diagnostics)
    {
        fileOffset = 0;
        virtualAddress = 0;
        if (!TryAlignUp(sourceLength, options.SegmentAlignment, out fileOffset))
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "The generated file placement alignment overflowed.");
            return false;
        }

        ulong highestVirtualEnd = 0;
        foreach (var header in sourceFile.ProgramHeaders.Where(header => header.Type == ElfConstants.PtLoad))
        {
            if (!TryAdd(header.VirtualAddress, header.MemorySize, out var end))
            {
                diagnostics.Error(DiagnosticCode.AddressOverflow, "An existing PT_LOAD virtual range overflowed.", header.VirtualAddress);
                return false;
            }

            highestVirtualEnd = Math.Max(highestVirtualEnd, end);
        }

        if (!TryAlignUp(highestVirtualEnd, options.SegmentAlignment, out virtualAddress))
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "The generated virtual placement alignment overflowed.");
            return false;
        }

        if (fileOffset % options.SegmentAlignment != virtualAddress % options.SegmentAlignment)
        {
            diagnostics.Error(DiagnosticCode.InvalidAlignment, "The generated file and virtual placements are not congruent.");
            return false;
        }

        return true;
    }

    private static bool TryFindExtensionHeader(
        ElfFile sourceFile,
        ulong sourceLength,
        out int index,
        out ProgramHeader header)
    {
        index = -1;
        header = default;
        var candidates = sourceFile.ProgramHeaders
            .Select((value, position) => (value, position))
            .Where(item => item.value.Type == ElfConstants.PtLoad
                && item.value.Flags == GeneratedSegmentPermissions
                && item.value.FileSize == item.value.MemorySize
                && TryAdd(item.value.Offset, item.value.FileSize, out var end)
                && end == sourceLength)
            .OrderByDescending(item => checked(item.value.VirtualAddress + item.value.MemorySize))
            .ThenBy(item => item.position)
            .ToArray();
        if (candidates.Length == 0)
        {
            return false;
        }

        index = candidates[0].position;
        header = candidates[0].value;
        return true;
    }

    private static bool TryFindNullHeader(IReadOnlyList<ProgramHeader> headers, out int index)
    {
        index = -1;
        for (var position = 0; position < headers.Count; position++)
        {
            if (headers[position].Type == ElfConstants.PtNull)
            {
                index = position;
                return true;
            }
        }

        return false;
    }

    private static ElfLayoutRange? GetSourceRange(ElfFile sourceFile, VirtualAddress address, ulong size)
    {
        if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(address, size, out var fileOffset))
        {
            return null;
        }

        return new ElfLayoutRange(fileOffset, address, size);
    }

    private static bool TryAlignPlacementCursor(
        ref ulong fileCursor,
        ref ulong virtualCursor,
        ulong alignment,
        ulong fileBase,
        ulong virtualBase,
        DiagnosticBag diagnostics)
    {
        if (!IsPowerOfTwo(alignment)
            || !TryAlignUp(fileCursor, alignment, out var alignedFile)
            || !TryAlignUp(virtualCursor, alignment, out var alignedVirtual))
        {
            diagnostics.Error(DiagnosticCode.InvalidAlignment, "A generated placement alignment is invalid.");
            return false;
        }

        if ((alignedFile - fileBase) != (alignedVirtual - virtualBase))
        {
            diagnostics.Error(DiagnosticCode.InvalidAlignment, "Generated file and virtual placement cursors diverged.");
            return false;
        }

        fileCursor = alignedFile;
        virtualCursor = alignedVirtual;
        return true;
    }

    private static void AddPaddingEdits(
        List<ElfLayoutByteEdit> edits,
        ulong start,
        ulong end,
        ElfLayoutOptions options,
        DiagnosticBag diagnostics)
    {
        if (end < start)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "Layout padding range underflowed.");
            return;
        }

        var size = end - start;
        if (size == 0)
        {
            return;
        }

        if (size > options.MaximumPaddingBytes || size > int.MaxValue)
        {
            diagnostics.Error(DiagnosticCode.ElfLayoutOutputLimitExceeded, "Layout padding exceeds its bounded materialization size.");
            return;
        }

        edits.Add(new ElfLayoutByteEdit(new FileOffset(start), new byte[checked((int)size)], ElfLayoutEditKind.Padding));
    }

    private static T[] ReadBounded<T>(IEnumerable<T> values, int maximum, out bool exceeded)
    {
        exceeded = false;
        var boundedMaximum = Math.Max(maximum, 1);
        var result = new List<T>(Math.Min(boundedMaximum, 1024));
        foreach (var value in values)
        {
            if (result.Count >= boundedMaximum)
            {
                exceeded = true;
                break;
            }

            result.Add(value);
        }

        return result.ToArray();
    }

    private static bool IntersectsProtectedSourceMetadata(ElfFile file, ulong offset, ulong size)
    {
        if (RangesOverlap(offset, size, 0, ElfConstants.HeaderSize64))
        {
            return true;
        }

        if (TryGetProgramHeaderTableRange(file, (ulong)file.Bytes.Length, out var table, out _)
            && RangesOverlap(offset, size, table.FileOffset.Value, table.Size))
        {
            return true;
        }

        return file.ProgramHeaders.Any(header =>
            header.Type != ElfConstants.PtLoad
            && header.FileSize > 0
            && RangesOverlap(offset, size, header.Offset, header.FileSize));
    }

    private static bool TryGetProgramHeaderTableRange(
        ElfFile file,
        ulong sourceLength,
        out ElfLayoutRange range,
        out ulong size)
    {
        range = default;
        size = 0;
        if (file.Header.ProgramHeaderOffset < ElfConstants.HeaderSize64
            || file.Header.ProgramHeaderEntrySize == 0
            || file.Header.ProgramHeaderCount == 0
            || !TryMultiply(
                file.Header.ProgramHeaderEntrySize,
                file.Header.ProgramHeaderCount,
                out size)
            || !TryAdd(file.Header.ProgramHeaderOffset, size, out var end)
            || end > sourceLength)
        {
            return false;
        }

        var hasVirtualAddress = file.LoadMap.TryFileOffsetToVirtualAddress(
            new FileOffset(file.Header.ProgramHeaderOffset),
            size,
            out var virtualAddress);
        range = new ElfLayoutRange(
            new FileOffset(file.Header.ProgramHeaderOffset),
            virtualAddress,
            size,
            hasVirtualAddress);
        return true;
    }

    private static byte[] SerializeProgramHeaders(IReadOnlyList<ProgramHeader> headers)
    {
        var bytes = new byte[checked(headers.Count * ElfConstants.ProgramHeaderSize64)];
        for (var index = 0; index < headers.Count; index++)
        {
            SerializeProgramHeader(headers[index]).CopyTo(bytes, checked(index * ElfConstants.ProgramHeaderSize64));
        }

        return bytes;
    }

    private static byte[] SerializeProgramHeader(ProgramHeader header)
    {
        var bytes = new byte[ElfConstants.ProgramHeaderSize64];
        var span = bytes.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(span[ElfProgramHeaderOffsets.Type..], header.Type);
        BinaryPrimitives.WriteUInt32LittleEndian(span[ElfProgramHeaderOffsets.Flags..], header.Flags);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.FileOffset..], header.Offset);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.VirtualAddress..], header.VirtualAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.PhysicalAddress..], header.PhysicalAddress);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.FileSize..], header.FileSize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.MemorySize..], header.MemorySize);
        BinaryPrimitives.WriteUInt64LittleEndian(span[ElfProgramHeaderOffsets.Alignment..], header.Alignment);
        return bytes;
    }

    private static ElfLayoutEvidence CreateEvidence(ElfLayoutPlan plan) =>
        new(
            ElfLayoutEvidence.CurrentSchemaVersion,
            plan.Strategy,
            plan.SourceSha256,
            string.Empty,
            plan.OutputLength,
            plan.OldProgramHeaderTable,
            plan.NewProgramHeaderTable,
            plan.PreservedMetadataSha256,
            plan.Placements,
            plan.AddressMap,
            plan.BranchDecisions)
        {
            TlsFixups = plan.TlsFixups,
        };

    private static string ComputePreservedMetadataFingerprint(IReadOnlyList<ProgramHeader> headers)
    {
        using var stream = new MemoryStream();
        foreach (var header in headers)
        {
            stream.Write(SerializeProgramHeader(header));
        }

        return Sha256(stream.ToArray());
    }

    private static bool EquivalentVeneerRequest(ElfLayoutVeneerRequest first, ElfLayoutVeneerRequest second) =>
        string.Equals(first.TargetIdentity, second.TargetIdentity, StringComparison.Ordinal)
        && first.MaximumBranchDistance == second.MaximumBranchDistance
        && first.Permissions == second.Permissions
        && first.Alignment == second.Alignment
        && first.CodeBytes.AsSpan().SequenceEqual(second.CodeBytes);

    private static bool EquivalentLongBranchRequest(ElfLayoutLongBranchRequest first, ElfLayoutLongBranchRequest second) =>
        first.Permissions == second.Permissions
        && first.Alignment == second.Alignment
        && first.CodeBytes.AsSpan().SequenceEqual(second.CodeBytes)
        && ((first.SourceReplacementBytes is null && second.SourceReplacementBytes is null)
            || (first.SourceReplacementBytes is not null
                && second.SourceReplacementBytes is not null
                && first.SourceReplacementBytes.AsSpan().SequenceEqual(second.SourceReplacementBytes)));

    private static bool IsValidIdentity(string value) =>
        !string.IsNullOrWhiteSpace(value)
        && value.Length <= ElfLayoutLimits.MaximumIdentityBytes
        && value.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or ':');

    private static bool IsBranchOpcode(uint opcode) =>
        (opcode & 0xFC000000u) is 0x14000000u or 0x94000000u;

    private static bool TryEncodeBranch26(
        uint opcode,
        ulong source,
        ulong target,
        out byte[] encoding,
        out long? displacement)
    {
        encoding = Array.Empty<byte>();
        displacement = null;
        if (!IsBranchOpcode(opcode)
            || (source & 3) != 0
            || (target & 3) != 0
            || !TryGetDisplacement(source, target, out var delta)
            || delta < ElfLayoutLimits.Branch26MinimumDisplacement
            || delta >= ElfLayoutLimits.Branch26MaximumDisplacementExclusive)
        {
            return false;
        }

        var value = (opcode & 0xFC000000u) | (uint)((delta >> 2) & 0x03FFFFFF);
        encoding = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(encoding, value);
        displacement = delta;
        return true;
    }

    private static bool TryGetDisplacement(ulong source, ulong target, out long displacement)
    {
        if (target >= source)
        {
            var delta = target - source;
            if (delta > long.MaxValue)
            {
                displacement = 0;
                return false;
            }

            displacement = (long)delta;
            return true;
        }

        var reverse = source - target;
        if (reverse > (ulong)long.MaxValue + 1)
        {
            displacement = 0;
            return false;
        }

        displacement = reverse == (ulong)long.MaxValue + 1
            ? long.MinValue
            : -(long)reverse;
        return true;
    }

    private static bool TryAlignUp(ulong value, ulong alignment, out ulong result)
    {
        result = 0;
        if (alignment == 0)
        {
            return false;
        }

        var remainder = value % alignment;
        if (remainder == 0)
        {
            result = value;
            return true;
        }

        var delta = alignment - remainder;
        if (value > ulong.MaxValue - delta)
        {
            return false;
        }

        result = value + delta;
        return true;
    }

    private static bool TryMultiply(ulong left, ulong right, out ulong result)
    {
        if (left != 0 && right > ulong.MaxValue / left)
        {
            result = 0;
            return false;
        }

        result = left * right;
        return true;
    }

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

    private static bool RangesOverlap(ulong firstStart, ulong firstSize, ulong secondStart, ulong secondSize)
    {
        return TryAdd(firstStart, firstSize, out var firstEnd)
            && TryAdd(secondStart, secondSize, out var secondEnd)
            && firstStart < secondEnd
            && secondStart < firstEnd;
    }

    private static bool IsPowerOfTwo(ulong value) => value != 0 && (value & (value - 1)) == 0;

    private static bool IsValidAlignment(ulong alignment, ulong maximum) =>
        alignment is 0 or 1 || alignment <= maximum && IsPowerOfTwo(alignment);

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record LayoutCandidate(ElfLayoutPlan Plan, CandidateScore Score);

    private readonly record struct CandidateScore(
        int TableRelocation,
        int ProgramHeaderCountDelta,
        int MetadataHeaderEdits,
        ulong PaddingBytes,
        int StrategyRank);
}
