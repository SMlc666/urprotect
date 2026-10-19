using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Integration;

public sealed class DynamicImportOwnerWorkflowTests
{
    private const string FixturePath = "Fixtures/DynamicImports/liburp-glob-dat-indirect.so";
    private const string UnitId = "dynamic-import.owner.glibc.host-context-entry";
    private const string ProducerId = "project-aarch64-glob-dat-import-fixture";
    private const string ConsumerId = "urprotect.rehydrator.v1";
    private static readonly string ProducerBuild = new('a', 64);
    private static readonly string ConsumerBuild = new('b', 64);

    [Fact]
    [Trait("Category", "Rehydration")]
    public void ProjectBuiltGlobDatCallFlowsThroughSnapshotProtectedImageAndRehydration()
    {
        var scenario = CreateScenario();
        var decodedImage = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(decodedImage.IsSuccess, string.Join(Environment.NewLine, decodedImage.Diagnostics));
        Assert.Single(decodedImage.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());

        var snapshotOperation = Assert.Single(
            decodedImage.Image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decodedSnapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(decodedSnapshot.IsSuccess, string.Join(Environment.NewLine, decodedSnapshot.Diagnostics));
        var owner = Assert.Single(decodedSnapshot.Snapshot!.Extensions.OfType<SemanticDynamicImportCallExtension>());
        Assert.Equal("getpid", owner.SymbolName);
        Assert.Equal((byte)0, owner.SymbolType);
        Assert.Equal((byte)1, owner.SymbolBinding);
        Assert.Equal((ushort)0, owner.SymbolSectionIndex);
        Assert.Null(owner.SymbolVersionIndexRaw);
        Assert.Equal(owner.RelocationOffset, owner.GotRange.VirtualAddress.Value);
        Assert.Equal(ElfConstants.RArm64GlobDat, (uint)(owner.RelocationInfo & uint.MaxValue));
        Assert.False(owner.RelocationIsPlt);
        Assert.Equal(owner.PageProducerAddress, owner.ProducerAddresses[0]);
        Assert.Equal(owner.LoadProducerAddress, owner.ProducerAddresses[^1]);
        Assert.Equal(3, owner.ProducerAddresses.Count);
        Assert.True(owner.ProducerAddresses[1].Value > owner.PageProducerAddress.Value);
        Assert.True(owner.ProducerAddresses[1].Value < owner.LoadProducerAddress.Value);
        Assert.Equal((byte)9, owner.TargetRegister.Index);
        var sourceElf = ElfParser.Parse(scenario.Source);
        Assert.True(sourceElf.IsSuccess, string.Join(Environment.NewLine, sourceElf.Diagnostics));
        var function = Assert.Single(sourceElf.File!.FunctionSymbols, symbol =>
            symbol.IsDynamic && string.Equals(symbol.Name, HostContextContract.EntrySymbol, StringComparison.Ordinal));
        Assert.Equal(new VirtualAddress(checked(function.Value + 24)), owner.CallAddress);
        var importedSymbol = sourceElf.File.DynamicSymbols[checked((int)owner.SymbolIndex)];
        Assert.Equal(owner.SymbolNameOffset, importedSymbol.Name);
        Assert.Equal(owner.SymbolInfo, importedSymbol.Info);
        Assert.Equal(owner.SymbolOther, importedSymbol.Other);
        Assert.Equal(owner.SymbolSectionIndex, importedSymbol.SectionIndex);
        Assert.Equal(owner.SymbolValue, importedSymbol.Value);
        Assert.Equal(owner.SymbolSize, importedSymbol.Size);
        var sourceRelocation = Assert.Single(sourceElf.File.RelaRelocations, relocation =>
            relocation.Offset == owner.RelocationOffset);
        Assert.Equal(owner.RelocationTableAddress.Value, sourceRelocation.SourceAddress);
        Assert.Equal(owner.RelocationInfo, sourceRelocation.Info);
        Assert.Equal(owner.RelocationAddend, sourceRelocation.Addend);
        Assert.False(sourceRelocation.IsPlt);
        Assert.True(sourceElf.File.LoadMap.TryVirtualAddressToFileOffset(
            owner.GotRange.VirtualAddress,
            owner.GotRange.Size,
            out var sourceGotFileOffset));
        Assert.Equal(owner.GotRange.FileOffset, sourceGotFileOffset);
        Assert.Single(decodedSnapshot.Snapshot.AddressMap.RelocationSites, entry =>
            entry.Identity == owner.RelocationSiteIdentity
            && entry.SourceRange == owner.GotRange);

        var rehydrated = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            scenario.Artifact,
            scenario.RehydrationOptions);
        Assert.True(rehydrated.IsSuccess, string.Join(Environment.NewLine, rehydrated.Diagnostics));
        Assert.NotNull(rehydrated.NativeImage);
        Assert.Equal(RehydrationRecord.PassedStatus, rehydrated.Record.Status);
        Assert.True(ElfParser.Parse(rehydrated.NativeImage!.Bytes).IsSuccess);
    }

    [Theory]
    [InlineData("call")]
    [InlineData("got")]
    [InlineData("rela")]
    [InlineData("dynsym")]
    [InlineData("address-map")]
    [InlineData("omitted-clobber")]
    [InlineData("remove-owner-edges")]
    [InlineData("remove-owner-forged-runtime-binding")]
    [InlineData("intervening-edge-forged-runtime-binding")]
    [InlineData("producer-after-call")]
    [InlineData("adrp-target")]
    [Trait("Category", "Rehydration")]
    public void RefreshedChecksumsDoNotLetTamperedImportOwnerPublishNativeImage(string edge)
    {
        var scenario = edge == "intervening-edge-forged-runtime-binding"
            ? CreateScenarioWithInterveningControlFlowEdge()
            : CreateScenario();
        var tamperedArtifact = edge is "producer-after-call" or "adrp-target"
            ? RefreshChecksumsAfterRawSnapshotTamper(scenario, edge)
            : RefreshChecksumsAfterTamper(scenario, edge);
        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            tamperedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticDynamicImportOwnerMismatch);
        if (edge == "remove-owner-forged-runtime-binding")
        {
            Assert.Contains(result.Diagnostics, diagnostic =>
                diagnostic.Code == DiagnosticCode.SemanticDynamicImportOwnerMismatch
                && diagnostic.Message.Contains(
                    "owner set does not match BLR calls independently derived",
                    StringComparison.Ordinal));
        }
        else if (edge == "intervening-edge-forged-runtime-binding")
        {
            Assert.Contains(result.Diagnostics, diagnostic =>
                diagnostic.Code == DiagnosticCode.SemanticDynamicImportOwnerMismatch
                && diagnostic.Message.Contains(
                    "provenance interval reaches a control-flow edge before its BLR call",
                    StringComparison.Ordinal));
        }
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void ExcessiveDynamicImportOwnersFailTheAggregateWorkBound()
    {
        var scenario = CreateScenario();
        var image = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256).Image!;
        var operation = Assert.Single(image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshot = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes).Snapshot!;
        var owner = Assert.Single(snapshot.Extensions.OfType<SemanticDynamicImportCallExtension>());
        var plan = snapshot.Plan;
        var oversizedPlan = new SemanticRewritePlan(
            plan.AddressMap,
            plan.Instructions,
            plan.Fixups,
            plan.Extensions.Concat(Enumerable.Repeat<ISemanticPlanExtension>(owner, 257)),
            plan.Diagnostics);

        var result = SemanticPlanSnapshotCodec.Create(oversizedPlan);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticDynamicImportOwnerMismatch
            && diagnostic.Message.Contains("bounded dynamic-import owner count", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsSelectedRegionsWhenTheEntireSemanticSnapshotIsRemoved()
    {
        var scenario = CreateScenario();
        var imageResult = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(imageResult.IsSuccess, string.Join(Environment.NewLine, imageResult.Diagnostics));
        var image = imageResult.Image!;
        var operations = image.Operations
            .Where(candidate => candidate is not ProtectedImageSemanticPlanSnapshot)
            .ToArray();
        var encoded = ProtectedImageCodec.Encode(image with { Operations = operations });
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            encoded.ArtifactBytes!,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);
    }

    private static Scenario CreateScenario(byte[]? sourceOverride = null)
    {
        var source = sourceOverride ?? File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var function = Assert.Single(parsed.File!.FunctionSymbols, symbol =>
            symbol.IsDynamic && string.Equals(symbol.Name, HostContextContract.EntrySymbol, StringComparison.Ordinal));
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, function.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var emitted = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                UnitId,
                ProtectedImageProfile.HostContextEntry,
                ProducerId,
                ProducerBuild,
                ConsumerId,
                sourceHash,
                requestHash));
        Assert.True(emitted.IsSuccess, string.Join(Environment.NewLine, emitted.Diagnostics));
        var artifact = emitted.ArtifactBytes!;
        var rehydrationOptions = new RehydrationOptions(
            sourceHash,
            emitted.Role!.RequestSha256,
            UnitId,
            ProtectedImageProfile.HostContextEntry,
            ProducerId,
            ProducerBuild,
            ConsumerId,
            ConsumerBuild);
        return new Scenario(source, sourceHash, requestHash, artifact, rehydrationOptions);
    }

    private static Scenario CreateScenarioWithInterveningControlFlowEdge()
    {
        var source = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var entry = Assert.Single(parsed.File!.FunctionSymbols, symbol =>
            symbol.IsDynamic && string.Equals(symbol.Name, HostContextContract.EntrySymbol, StringComparison.Ordinal));
        var branchAddress = new VirtualAddress(checked(entry.Value + 12));
        Assert.True(parsed.File.LoadMap.TryVirtualAddressToFileOffset(
            branchAddress,
            sizeof(uint),
            out var branchOffset));
        var branchSite = checked((int)branchOffset.Value);
        Assert.Equal(
            0xAA1F03E1u,
            BinaryPrimitives.ReadUInt32LittleEndian(source.AsSpan(branchSite, sizeof(uint))));
        BinaryPrimitives.WriteUInt32LittleEndian(source.AsSpan(branchSite, sizeof(uint)), 0x14000001u);
        return CreateScenario(source);
    }

    private static byte[] RefreshChecksumsAfterTamper(Scenario scenario, string edge)
    {
        var imageResult = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(imageResult.IsSuccess, string.Join(Environment.NewLine, imageResult.Diagnostics));
        var image = imageResult.Image!;
        var operation = Assert.Single(image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decodedSnapshot = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decodedSnapshot.IsSuccess, string.Join(Environment.NewLine, decodedSnapshot.Diagnostics));
        var sourcePlan = decodedSnapshot.Snapshot!.Plan;
        var mapEntries = sourcePlan.AddressMap.Entries.ToArray();
        var instructions = sourcePlan.Instructions.ToArray();
        var extensions = sourcePlan.Extensions.ToList();
        var ownerIndex = extensions.FindIndex(extension => extension is SemanticDynamicImportCallExtension);
        Assert.True(ownerIndex >= 0);
        var owner = (SemanticDynamicImportCallExtension)extensions[ownerIndex];

        switch (edge)
        {
            case "call":
            {
                var fakeCallMap = Assert.Single(mapEntries, entry => entry.Identity == owner.CallIdentity);
                var fakeAddress = instructions
                    .Where(instruction => string.Equals(instruction.Mnemonic, "RET", StringComparison.OrdinalIgnoreCase))
                    .MinBy(instruction => instruction.SourceVirtualAddress.Value)!
                    .SourceVirtualAddress;
                var fakeEntry = Assert.Single(mapEntries, entry =>
                    entry.Identity == SemanticEntityId.Instruction(fakeAddress));
                var sourceCall = Assert.Single(instructions, instruction => instruction.SourceVirtualAddress == owner.CallAddress);
                var fakeCall = new SemanticInstruction(
                    fakeAddress,
                    fakeEntry.SourceRange.FileOffset,
                    sourceCall.Encoding,
                    sourceCall.Mnemonic,
                    fakeEntry.SourceRange,
                    sourceCall.Operands,
                    sourceCall.RegisterEffects,
                    sourceCall.FlagEffects,
                    sourceCall.ControlFlow,
                    sourceCall.ControlFlowTarget,
                    sourceCall.PcRelativeExpression,
                    sourceCall.LiteralReference,
                    sourceCall.Relocations,
                    sourceCall.References,
                    sourceCall.OpaquePreservation);
                instructions = instructions
                    .Where(instruction => instruction.SourceVirtualAddress != fakeAddress)
                    .Append(fakeCall)
                    .ToArray();
                var changedOwner = CopyOwner(owner, callAddress: fakeAddress);
                extensions[ownerIndex] = changedOwner;
                var indirectIndex = extensions.FindIndex(extension =>
                    extension is SemanticIndirectTargetExtension target
                    && target.SourceAddress == owner.CallAddress);
                var originalTarget = Assert.IsType<SemanticIndirectTargetExtension>(extensions[indirectIndex]);
                extensions[indirectIndex] = new SemanticIndirectTargetExtension(
                    SemanticEntityId.Instruction(fakeAddress),
                    fakeAddress,
                    originalTarget.Target,
                    originalTarget.Diagnostic);
                _ = fakeCallMap;
                break;
            }
            case "got":
            {
                var changedRange = owner.GotRange with
                {
                    FileOffset = new FileOffset(checked(owner.GotRange.FileOffset.Value + 1)),
                };
                extensions[ownerIndex] = CopyOwner(owner, gotRange: changedRange);
                mapEntries = mapEntries.Select(entry => entry.Identity.Kind switch
                {
                    SemanticEntityKind.RelocationTarget when entry.SourceRange == owner.GotRange =>
                        entry with { SourceRange = changedRange },
                    SemanticEntityKind.RelocationSite when entry.Identity == owner.RelocationSiteIdentity =>
                        entry with { SourceRange = changedRange },
                    _ => entry,
                }).ToArray();
                break;
            }
            case "rela":
            {
                var changedTableAddress = new VirtualAddress(checked(owner.RelocationTableAddress.Value + 8));
                extensions[ownerIndex] = CopyOwner(owner, relocationTableAddress: changedTableAddress);
                var relocationIndex = extensions.FindIndex(extension =>
                    extension is SemanticRelocationBindingExtension relocation
                    && relocation.RelocationSite == owner.RelocationSiteIdentity);
                var oldRelocation = Assert.IsType<SemanticRelocationBindingExtension>(extensions[relocationIndex]);
                extensions[relocationIndex] = new SemanticRelocationBindingExtension(
                    oldRelocation.RelocationSite,
                    oldRelocation.Binding with { RelocationTableAddress = changedTableAddress },
                    oldRelocation.Diagnostic);
                break;
            }
            case "dynsym":
                extensions[ownerIndex] = CopyOwner(owner, symbolNameOffset: checked(owner.SymbolNameOffset + 1));
                break;
            case "omitted-clobber":
            {
                var clobberAddress = new VirtualAddress(checked(owner.PageProducerAddress.Value + 8));
                Assert.Contains(instructions, instruction => instruction.SourceVirtualAddress == clobberAddress);
                instructions = instructions.Where(instruction => instruction.SourceVirtualAddress != clobberAddress).ToArray();
                break;
            }
            case "remove-owner-edges":
                extensions.RemoveAll(extension => extension is SemanticDynamicImportCallExtension
                    || extension is SemanticIndirectTargetExtension target && target.SourceAddress == owner.CallAddress
                    || extension is SemanticRelocationBindingExtension relocation && relocation.RelocationSite == owner.RelocationSiteIdentity);
                break;
            case "remove-owner-forged-runtime-binding":
            case "intervening-edge-forged-runtime-binding":
            {
                var forgedBinding = SemanticTarget.RuntimeResolved("fixture:forged-runtime-target");
                var callInstructionIndex = Array.FindIndex(instructions, instruction =>
                    instruction.SourceVirtualAddress == owner.CallAddress);
                Assert.True(callInstructionIndex >= 0);
                var sourceCall = instructions[callInstructionIndex];
                var references = sourceCall.References
                    .Select(reference => reference.Kind == SemanticReferenceKind.ControlFlowTarget
                        ? reference with { Target = forgedBinding }
                        : reference)
                    .ToArray();
                instructions[callInstructionIndex] = new SemanticInstruction(
                    sourceCall.SourceVirtualAddress,
                    sourceCall.SourceFileOffset,
                    sourceCall.Encoding,
                    sourceCall.Mnemonic,
                    sourceCall.SourceRange,
                    sourceCall.Operands,
                    sourceCall.RegisterEffects,
                    sourceCall.FlagEffects,
                    sourceCall.ControlFlow,
                    forgedBinding,
                    sourceCall.PcRelativeExpression,
                    sourceCall.LiteralReference,
                    sourceCall.Relocations,
                    references,
                    sourceCall.OpaquePreservation);

                var indirectIndex = extensions.FindIndex(extension =>
                    extension is SemanticIndirectTargetExtension target
                    && target.SourceAddress == owner.CallAddress);
                var originalTarget = Assert.IsType<SemanticIndirectTargetExtension>(extensions[indirectIndex]);
                extensions[indirectIndex] = new SemanticIndirectTargetExtension(
                    originalTarget.SourceInstruction,
                    originalTarget.SourceAddress,
                    forgedBinding,
                    originalTarget.Diagnostic);
                extensions.RemoveAll(extension => extension is SemanticDynamicImportCallExtension
                    || extension is SemanticRelocationBindingExtension relocation
                        && relocation.RelocationSite == owner.RelocationSiteIdentity);
                break;
            }
            case "address-map":
            {
                var siteEntryIndex = Array.FindIndex(mapEntries, entry => entry.Identity == owner.RelocationSiteIdentity);
                var oldSiteEntry = mapEntries[siteEntryIndex];
                mapEntries[siteEntryIndex] = oldSiteEntry with
                {
                    OutputRange = oldSiteEntry.OutputRange with
                    {
                        FileOffset = new FileOffset(checked(oldSiteEntry.OutputRange.FileOffset.Value + 8)),
                    },
                };
                break;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(edge));
        }

        var map = AddressMap.Create(mapEntries);
        Assert.True(map.IsSuccess, string.Join(Environment.NewLine, map.Diagnostics));
        var tamperedPlan = new SemanticRewritePlan(
            map.Map!,
            instructions,
            sourcePlan.Fixups,
            extensions,
            sourcePlan.Diagnostics);
        var canonical = SemanticPlanSnapshotCodec.Create(tamperedPlan);
        Assert.True(canonical.IsSuccess, string.Join(Environment.NewLine, canonical.Diagnostics));
        var operations = image.Operations
            .Select(candidate => candidate is ProtectedImageSemanticPlanSnapshot
                ? new ProtectedImageSemanticPlanSnapshot(canonical.Snapshot!)
                : candidate)
            .ToArray();
        var encodedImage = ProtectedImageCodec.Encode(image with { Operations = operations });
        Assert.True(encodedImage.IsSuccess, string.Join(Environment.NewLine, encodedImage.Diagnostics));
        return encodedImage.ArtifactBytes!;
    }

    private static byte[] RefreshChecksumsAfterRawSnapshotTamper(Scenario scenario, string edge)
    {
        var imageResult = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(imageResult.IsSuccess, string.Join(Environment.NewLine, imageResult.Diagnostics));
        var image = imageResult.Image!;
        var operation = Assert.Single(image.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var owner = Assert.Single(decoded.Snapshot!.Extensions.OfType<SemanticDynamicImportCallExtension>());
        var originalBytes = operation.CanonicalBytes;
        var tamperedBytes = originalBytes.ToArray();

        switch (edge)
        {
            case "producer-after-call":
            {
                var sequence = new byte[owner.ProducerAddresses.Count * sizeof(ulong)];
                for (var index = 0; index < owner.ProducerAddresses.Count; index++)
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(
                        sequence.AsSpan(index * sizeof(ulong), sizeof(ulong)),
                        owner.ProducerAddresses[index].Value);
                }

                var sequenceOffset = FindUniquePattern(originalBytes, sequence);
                BinaryPrimitives.WriteUInt64LittleEndian(
                    tamperedBytes.AsSpan(sequenceOffset + ((owner.ProducerAddresses.Count - 1) * sizeof(ulong)), sizeof(ulong)),
                    checked(owner.CallAddress.Value + sizeof(uint)));
                break;
            }
            case "adrp-target":
            {
                var pageBytes = new byte[sizeof(ulong)];
                BinaryPrimitives.WriteUInt64LittleEndian(pageBytes, owner.PageAddress.Value);
                var payload = originalBytes.AsSpan(0, originalBytes.Length - 32).ToArray();
                var searchOffset = 0;
                var foundExpressionTarget = false;
                while ((searchOffset = FindPattern(payload, pageBytes, searchOffset)) >= 0)
                {
                    var candidateBytes = originalBytes.ToArray();
                    BinaryPrimitives.WriteUInt64LittleEndian(
                        candidateBytes.AsSpan(searchOffset, sizeof(ulong)),
                        checked(owner.PageAddress.Value + 0x1000));
                    RefreshSnapshotDigest(candidateBytes);
                    var candidate = SemanticPlanSnapshotCodec.Decode(candidateBytes);
                    if (!candidate.IsSuccess && candidate.Diagnostics.Any(diagnostic =>
                            diagnostic.Code == DiagnosticCode.SemanticDynamicImportOwnerMismatch
                            && diagnostic.Message.Contains("ADRP page producer", StringComparison.Ordinal)))
                    {
                        tamperedBytes = candidateBytes;
                        foundExpressionTarget = true;
                        break;
                    }

                    searchOffset++;
                }

                Assert.True(foundExpressionTarget, "The canonical ADRP PC-relative target did not have a checksum-refreshed rejection witness.");
                break;
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(edge));
        }

        RefreshSnapshotDigest(tamperedBytes);
        var refreshed = SemanticPlanSnapshotCodec.Decode(tamperedBytes);
        if (edge == "producer-after-call")
        {
            Assert.False(refreshed.IsSuccess);
            Assert.Contains(refreshed.Diagnostics, diagnostic =>
                diagnostic.Code == DiagnosticCode.SemanticDynamicImportOwnerMismatch);
        }

        var artifact = scenario.Artifact.ToArray();
        var embeddedOffset = FindUniquePattern(artifact, originalBytes);
        tamperedBytes.CopyTo(artifact.AsSpan(embeddedOffset));
        SHA256.HashData(tamperedBytes).CopyTo(artifact.AsSpan(embeddedOffset - 32, 32));
        SHA256.HashData(artifact.AsSpan(0, artifact.Length - 32)).CopyTo(artifact.AsSpan(artifact.Length - 32));
        return artifact;
    }

    private static void RefreshSnapshotDigest(byte[] canonicalBytes)
    {
        var digestOffset = canonicalBytes.Length - 32;
        SHA256.HashData(canonicalBytes.AsSpan(0, digestOffset)).CopyTo(canonicalBytes.AsSpan(digestOffset));
    }

    private static int FindUniquePattern(byte[] bytes, byte[] pattern)
    {
        var first = FindPattern(bytes, pattern);
        Assert.True(first >= 0, "The requested byte pattern was not present.");
        Assert.Equal(-1, FindPattern(bytes, pattern, first + 1));
        return first;
    }

    private static int FindPattern(byte[] bytes, byte[] pattern, int startIndex = 0)
    {
        for (var index = startIndex; index <= bytes.Length - pattern.Length; index++)
        {
            if (bytes.AsSpan(index, pattern.Length).SequenceEqual(pattern))
            {
                return index;
            }
        }

        return -1;
    }

    private static SemanticDynamicImportCallExtension CopyOwner(
        SemanticDynamicImportCallExtension owner,
        VirtualAddress? callAddress = null,
        SemanticSourceRange? gotRange = null,
        VirtualAddress? relocationTableAddress = null,
        uint? symbolNameOffset = null) =>
        new(
            callAddress is { } changedCall ? SemanticEntityId.Instruction(changedCall) : owner.CallIdentity,
            callAddress ?? owner.CallAddress,
            owner.TargetRegister,
            owner.ProducerAddresses,
            owner.PageProducerAddress,
            owner.LoadProducerAddress,
            owner.PageAddress,
            gotRange ?? owner.GotRange,
            owner.RelocationSiteIdentity,
            owner.RelocationOffset,
            owner.RelocationInfo,
            owner.RelocationAddend,
            owner.RelocationIsPlt,
            relocationTableAddress ?? owner.RelocationTableAddress,
            owner.SymbolIndex,
            symbolNameOffset ?? owner.SymbolNameOffset,
            owner.SymbolName,
            owner.SymbolInfo,
            owner.SymbolOther,
            owner.SymbolBinding,
            owner.SymbolType,
            owner.SymbolVisibility,
            owner.SymbolSectionIndex,
            owner.SymbolValue,
            owner.SymbolSize,
            owner.SymbolVersionIndexRaw,
            owner.VersionRequirement);

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed record Scenario(
        byte[] Source,
        string SourceSha256,
        string RequestSha256,
        byte[] Artifact,
        RehydrationOptions RehydrationOptions);
}
