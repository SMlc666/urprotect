using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Integration;

public sealed class StaticFunctionPointerOwnerWorkflowTests
{
    private const string FixturePath = "Fixtures/StaticFunctionPointers/liburp-static-function-pointer.so";
    private const string UnitId = "static-function-pointer.owner.glibc.host-context-entry";
    private const string ProducerId = "project-aarch64-static-function-pointer-fixture";
    private const string ConsumerId = "urprotect.rehydrator.v1";
    private static readonly string ProducerBuild = new('c', 64);
    private static readonly string ConsumerBuild = new('d', 64);

    [Fact]
    [Trait("Category", "Rehydration")]
    public void StaticLocalCallbackFlowsThroughStrictSnapshotAndPublicationRevalidation()
    {
        var scenario = CreateScenario();
        var image = ProtectedImageCodec.Decode(
            scenario.Artifact,
            scenario.SourceSha256,
            scenario.RequestSha256);
        Assert.True(image.IsSuccess, Describe(image.Diagnostics));
        var snapshotOperation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        var snapshot = decoded.Snapshot!;
        var owner = Assert.Single(snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>());
        Assert.Empty(snapshot.Extensions.OfType<SemanticDynamicImportCallExtension>());
        Assert.Equal("urp_entry", owner.OwnerFunction.Name);
        Assert.Equal(ElfSymbolTableKind.Dynamic, owner.OwnerFunction.Table);
        Assert.Equal("urp_static_callback", owner.AdrpRelocation.Name);
        Assert.Equal((byte)2, (byte)(owner.AdrpRelocation.SymbolInfo & 0x0F));
        Assert.Equal((byte)0, (byte)(owner.AdrpRelocation.SymbolInfo >> 4));
        Assert.Equal((byte)0, (byte)(owner.AdrpRelocation.SymbolOther & 0x03));
        Assert.Equal(ElfConstants.RArm64AdrPrelPgHi21, owner.AdrpRelocation.Type);
        Assert.Equal(ElfConstants.RArm64AddAbsLo12Nc, owner.AddRelocation.Type);
        Assert.Equal(owner.TargetSourceRange, owner.TargetOutputRange);
        Assert.Equal(SemanticStaticFunctionPointerMappingPolicy.PreserveOriginalAddress, owner.MappingPolicy);
        Assert.Equal(4, owner.ProducerAddresses.Count);
        Assert.True(owner.ProducerAddresses.Zip(owner.ProducerAddresses.Skip(1),
            (left, right) => right.Value == left.Value + sizeof(uint)).All(adjacent => adjacent));
        var indirectTarget = Assert.Single(snapshot.Extensions.OfType<SemanticIndirectTargetExtension>(),
            target => target.SourceAddress == owner.CallAddress);
        Assert.True(indirectTarget.Target.IsExact);
        Assert.Equal(owner.TargetMappingIdentity, indirectTarget.Target.Identity);
        Assert.Equal(owner.TargetSourceRange.VirtualAddress, indirectTarget.Target.SourceAddress);
        Assert.Single(snapshot.AddressMap.Entries, entry =>
            entry.Identity == owner.TargetMappingIdentity
            && entry.SourceRange == owner.TargetSourceRange
            && entry.OutputRange == owner.TargetOutputRange);

        var source = ElfParser.Parse(scenario.Source);
        Assert.True(source.IsSuccess, Describe(source.Diagnostics));
        Assert.True(source.File!.LoadMap.TryVirtualAddressToFileOffset(
            owner.TargetSourceRange.VirtualAddress,
            owner.TargetSourceRange.Size,
            out var targetFileOffset));
        Assert.Equal(owner.TargetSourceRange.FileOffset, targetFileOffset);
        var rehydrated = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            scenario.Artifact,
            scenario.RehydrationOptions);
        Assert.True(rehydrated.IsSuccess, Describe(rehydrated.Diagnostics));
        Assert.NotNull(rehydrated.NativeImage);
        Assert.Equal(RehydrationRecord.PassedStatus, rehydrated.Record.Status);
        Assert.True(ElfParser.Parse(rehydrated.NativeImage!.Bytes).IsSuccess);
        var output = ElfParser.Parse(rehydrated.NativeImage.Bytes).File!;
        Assert.True(output.LoadMap.TryVirtualAddressToFileOffset(
            owner.TargetOutputRange.VirtualAddress,
            owner.TargetOutputRange.Size,
            out var outputTargetFileOffset));
        Assert.Equal(
            scenario.Source.AsSpan(checked((int)targetFileOffset.Value), checked((int)owner.TargetSourceRange.Size)).ToArray(),
            rehydrated.NativeImage.Bytes.AsSpan(
                checked((int)outputTargetFileOffset.Value),
                checked((int)owner.TargetOutputRange.Size)).ToArray());
        var sourceObserver = Assert.Single(source.File.FunctionSymbols, symbol =>
            symbol.IsDynamic && symbol.Name == "urp_observer");
        var outputObserver = Assert.Single(output.FunctionSymbols, symbol =>
            symbol.Table == sourceObserver.Table && symbol.TableIndex == sourceObserver.TableIndex);
        Assert.Equal(sourceObserver.Value, outputObserver.Value);
        Assert.Equal(sourceObserver.Size, outputObserver.Size);
        Assert.True(source.File.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(sourceObserver.Value),
            sourceObserver.Size,
            out var sourceObserverOffset));
        Assert.True(output.LoadMap.TryVirtualAddressToFileOffset(
            new VirtualAddress(outputObserver.Value),
            outputObserver.Size,
            out var outputObserverOffset));
        Assert.Equal(
            scenario.Source.AsSpan(checked((int)sourceObserverOffset.Value), checked((int)sourceObserver.Size)).ToArray(),
            rehydrated.NativeImage.Bytes.AsSpan(
                checked((int)outputObserverOffset.Value),
                checked((int)outputObserver.Size)).ToArray());
    }

    [Theory]
    [InlineData("without-sections")]
    [InlineData("missing-relocation-row")]
    [InlineData("malformed-relocation-pair")]
    [InlineData("sh-link")]
    [InlineData("sh-info")]
    [InlineData("symbol-index")]
    [InlineData("relocation-type")]
    [InlineData("addend")]
    [InlineData("target-owning-section")]
    [InlineData("non-function-target")]
    [InlineData("undefined-target")]
    [InlineData("preemptible-target")]
    [InlineData("out-of-range-target")]
    [InlineData("unmapped-target")]
    [InlineData("changed-adrp-expression")]
    [InlineData("changed-add-expression")]
    [InlineData("target-register-clobber")]
    [InlineData("altered-stack-slot")]
    [InlineData("conflicting-control-flow-branch")]
    [InlineData("arbitrary-runtime-pointer")]
    [Trait("Category", "Protect")]
    public void StaticLocalCallbackProofRejectsEachNearestUnsafeInputBeforePublication(string mutation)
    {
        var bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));
        var parsed = ElfParser.Parse(bytes);
        Assert.True(parsed.IsSuccess, Describe(parsed.Diagnostics));
        var function = Assert.Single(parsed.File!.FunctionSymbols, symbol =>
            symbol.IsDynamic && symbol.Name == "urp_entry");
        var mutated = Mutate(bytes, parsed.File, function, mutation);
        var mutatedParse = ElfParser.Parse(mutated);
        Assert.True(mutatedParse.IsSuccess, $"{mutation} must reach semantic validation, not fail ELF parsing: {Describe(mutatedParse.Diagnostics)}");
        var mutatedFunction = Assert.Single(mutatedParse.File!.FunctionSymbols, symbol =>
            symbol.Table == function.Table && symbol.TableIndex == function.TableIndex);
        AssertMutationReachedItsNamedBoundary(mutated, mutatedParse.File, mutatedFunction, mutation);

        var analysis = new Aarch64FunctionAnalyzer().Analyze(mutatedParse.File, mutatedFunction);
        Assert.Empty(analysis.StaticFunctionPointerCallResolutions);
        Assert.False(analysis.IsComplete);
        var proofFailure = Assert.Single(analysis.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
        Assert.Contains(ExpectedProofFailure(mutation), proofFailure.Message, StringComparison.Ordinal);

        // The selected-function producer is the publication boundary for this source proof.
        // No Protected Image bytes/role are returned, so no Native Image or loader handoff can follow.
        var emitted = EmitProtectedImage(mutated, mutatedFunction);
        Assert.False(emitted.IsSuccess);
        Assert.Null(emitted.ArtifactBytes);
        Assert.Null(emitted.Role);
        Assert.Contains(emitted.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void OutputStaticCallbackAdrpEncodeFailurePreventsProtectedImagePublication()
    {
        var bytes = File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));
        var parsed = ElfParser.Parse(bytes);
        Assert.True(parsed.IsSuccess, Describe(parsed.Diagnostics));
        var function = Assert.Single(parsed.File!.FunctionSymbols, symbol =>
            symbol.IsDynamic && symbol.Name == "urp_entry");
        var callback = Assert.Single(parsed.File.FunctionSymbols, symbol =>
            !symbol.IsDynamic && symbol.Name == "urp_static_callback");
        var rejectingEncoder = new RejectCallbackAdrpEncoder(new Aarch64InstructionEncoder(), callback.Value);
        var service = new FunctionProtectionService(encoder: rejectingEncoder);
        var request = CreateRequest(function);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var emitted = new ProtectedImageProducer(new ProtectionWorkflow(service)).Emit(
            bytes,
            request,
            ProducerOptions(bytes, requestHash));

        Assert.True(rejectingEncoder.Rejected, "the production emitter must submit the preserved callback ADRP to the adapter");
        Assert.False(emitted.IsSuccess);
        Assert.Null(emitted.ArtifactBytes);
        Assert.Null(emitted.Role);
        Assert.Contains(emitted.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);

        var realEncoder = new Aarch64InstructionEncoder();
        var sourceAdrp = realEncoder.TryCreate(new Aarch64InstructionBuildRequest(
            Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            Address: 0x1000,
            TargetOrImmediate: 0x2000,
            DestinationRegister: 1));
        Assert.True(sourceAdrp.IsSuccess, sourceAdrp.Diagnostic);
        var outOfRange = realEncoder.TryEncode(new Aarch64InstructionEncodeRequest(
            sourceAdrp.Encoding,
            SourceAddress: 0x1000,
            OutputAddress: 0x1000,
            Family: Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
            TargetOrImmediate: 0x100001000));
        Assert.False(outOfRange.IsSuccess);
        Assert.Equal(Aarch64InstructionEncodeDiagnosticCode.TargetOutOfRange, outOfRange.DiagnosticCode);
        Assert.Equal(0u, outOfRange.Encoding);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsRefreshedSnapshotWithForgedTargetSectionIdentity()
    {
        var scenario = CreateScenario();
        var tamperedArtifact = ReencodeSnapshot(scenario, snapshot =>
        {
            var plan = snapshot.Plan;
            var owners = plan.Extensions.ToList();
            var ownerIndex = owners.FindIndex(extension => extension is SemanticStaticFunctionPointerCallExtension);
            var owner = (SemanticStaticFunctionPointerCallExtension)owners[ownerIndex];
            owners[ownerIndex] = new SemanticStaticFunctionPointerCallExtension(
                owner.SourceIdentity,
                owner.SourceRange,
                owner.TargetRegister,
                owner.ProducerAddresses,
                owner.StackSlotOffset,
                owner.OwnerFunction,
                owner.RelocationSectionIndex,
                owner.RelocationSectionHeader,
                owner.SymbolTableSectionIndex,
                owner.SymbolTableSectionHeader,
                owner.CallerSectionHeader,
                owner.TargetSectionHeader with { Name = owner.TargetSectionHeader.Name + 1 },
                owner.AdrpRelocation,
                owner.AddRelocation,
                owner.TargetSourceRange,
                owner.TargetMappingIdentity,
                owner.TargetOutputRange,
                owner.MappingPolicy);
            return new SemanticRewritePlan(plan.AddressMap, plan.Instructions, plan.Fixups, owners, plan.Diagnostics);
        });

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            tamperedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Message.Contains("independent source CFG", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsOmittedStaticCallbackOwnerWithRefreshedSnapshotAndArtifactDigests()
    {
        var scenario = CreateScenario();
        var tamperedArtifact = ReencodeSnapshot(scenario, snapshot =>
        {
            var plan = snapshot.Plan;
            var extensions = plan.Extensions
                .Where(extension => extension is not SemanticStaticFunctionPointerCallExtension)
                .ToArray();
            return new SemanticRewritePlan(plan.AddressMap, plan.Instructions, plan.Fixups, extensions, plan.Diagnostics);
        });

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            tamperedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved
            && diagnostic.Message.Contains("without exactly one carried typed owner", StringComparison.Ordinal));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsRefreshedForgedCallbackIdentityMapBeforeNativePublication()
    {
        var scenario = CreateScenario();
        var tamperedArtifact = ReencodeSnapshot(scenario, snapshot =>
        {
            var plan = snapshot.Plan;
            var owners = plan.Extensions.ToArray();
            var ownerIndex = Array.FindIndex(owners, extension => extension is SemanticStaticFunctionPointerCallExtension);
            var owner = (SemanticStaticFunctionPointerCallExtension)owners[ownerIndex];
            const string forgedName = "urp_forged_callback";
            var forgedIdentity = SemanticEntityId.RelocationTarget(
                $"static-function:{owner.SymbolTableSectionIndex}:{owner.AdrpRelocation.SymbolIndex}:{forgedName}");
            var forgedAdrp = owner.AdrpRelocation with { Name = forgedName };
            var forgedAdd = owner.AddRelocation with { Name = forgedName };
            owners[ownerIndex] = CopyOwner(owner, forgedAdrp, forgedAdd, forgedIdentity);
            for (var index = 0; index < owners.Length; index++)
            {
                if (owners[index] is SemanticIndirectTargetExtension target
                    && target.SourceAddress == owner.CallAddress)
                {
                    owners[index] = new SemanticIndirectTargetExtension(
                        target.SourceInstruction,
                        target.SourceAddress,
                        SemanticTarget.Exact(forgedIdentity, owner.TargetSourceRange.VirtualAddress),
                        target.Diagnostic);
                }
            }

            var mappings = plan.AddressMap.Entries.Select(entry =>
                entry.Identity == owner.TargetMappingIdentity
                    ? entry with { Identity = forgedIdentity, OutputIdentity = forgedIdentity }
                    : entry);
            var forgedMap = AddressMap.Create(mappings);
            Assert.True(forgedMap.IsSuccess, Describe(forgedMap.Diagnostics));
            return new SemanticRewritePlan(forgedMap.Map!, plan.Instructions, plan.Fixups, owners, plan.Diagnostics);
        });

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            tamperedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationRejectsMissingCallbackIdentityMapWithRefreshedSnapshotAndArtifactDigests()
    {
        var scenario = CreateScenario();
        var image = ProtectedImageCodec.Decode(scenario.Artifact, scenario.SourceSha256, scenario.RequestSha256);
        Assert.True(image.IsSuccess, Describe(image.Diagnostics));
        var operation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        var owner = Assert.Single(decoded.Snapshot!.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>());
        var missingMapSnapshot = RemoveAddressMapEntry(operation.CanonicalBytes, owner.TargetMappingIdentity);
        var tamperedArtifact = ReplaceSnapshotAndRefreshDigests(
            scenario.Artifact,
            operation.CanonicalBytes,
            missingMapSnapshot);

        var result = GenericRehydrationEngine.Rehydrate(
            scenario.Source,
            tamperedArtifact,
            scenario.RehydrationOptions);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void SnapshotRejectsMissingCallbackIdentityMapBeforeProtectedImageEncoding()
    {
        var scenario = CreateScenario();
        var image = ProtectedImageCodec.Decode(scenario.Artifact, scenario.SourceSha256, scenario.RequestSha256);
        Assert.True(image.IsSuccess, Describe(image.Diagnostics));
        var operation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        var snapshot = decoded.Snapshot!;
        var owner = Assert.Single(snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>());
        var map = AddressMap.Create(snapshot.AddressMap.Entries
            .Where(entry => entry.Identity != owner.TargetMappingIdentity));
        Assert.True(map.IsSuccess, Describe(map.Diagnostics));
        var incompletePlan = new SemanticRewritePlan(
            map.Map!,
            snapshot.Plan.Instructions,
            snapshot.Plan.Fixups,
            snapshot.Plan.Extensions,
            snapshot.Plan.Diagnostics);

        var rejected = SemanticPlanSnapshotCodec.Create(incompletePlan);

        Assert.False(rejected.IsSuccess);
        Assert.Null(rejected.Snapshot);
        Assert.Contains(rejected.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.IndirectTargetUnresolved);
        // Snapshot validation fails before a Protected Image operation/artifact can be encoded.
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void StaticCallSnapshotVersionIsStrictlyV6AndRoundTripsTypedRows()
    {
        var scenario = CreateScenario();
        var image = ProtectedImageCodec.Decode(scenario.Artifact, scenario.SourceSha256, scenario.RequestSha256);
        Assert.True(image.IsSuccess, Describe(image.Diagnostics));
        var operation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        var call = Assert.Single(decoded.Snapshot!.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>());
        Assert.Equal((ushort)6, SemanticPlanSnapshotCodec.Version);
        Assert.Equal("URP-SPS6", SemanticPlanSnapshotCodec.MagicText);
        var roundTrip = SemanticPlanSnapshotCodec.Decode(decoded.Snapshot.CanonicalBytes);
        Assert.True(roundTrip.IsSuccess, Describe(roundTrip.Diagnostics));
        Assert.Equal(decoded.Snapshot.CanonicalBytes, roundTrip.Snapshot!.CanonicalBytes);
        Assert.Equal(call.CallAddress, Assert.Single(
            roundTrip.Snapshot.Extensions.OfType<SemanticStaticFunctionPointerCallExtension>()).CallAddress);

        foreach (ushort version in new ushort[] { 1, 2, 3, 4, 5 })
        {
            var bytes = decoded.Snapshot.CanonicalBytes;
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(8, sizeof(ushort)), version);
            RefreshSnapshotDigest(bytes);
            var rejected = SemanticPlanSnapshotCodec.Decode(bytes);
            Assert.False(rejected.IsSuccess);
            Assert.Null(rejected.Snapshot);
            Assert.Contains(rejected.Diagnostics, diagnostic =>
                diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotUnsupported);
        }
    }

    private static SemanticStaticFunctionPointerCallExtension CopyOwner(
        SemanticStaticFunctionPointerCallExtension owner,
        SemanticStaticFunctionPointerRelocationRow adrp,
        SemanticStaticFunctionPointerRelocationRow add,
        SemanticEntityId targetIdentity) =>
        new(
            owner.SourceIdentity,
            owner.SourceRange,
            owner.TargetRegister,
            owner.ProducerAddresses,
            owner.StackSlotOffset,
            owner.OwnerFunction,
            owner.RelocationSectionIndex,
            owner.RelocationSectionHeader,
            owner.SymbolTableSectionIndex,
            owner.SymbolTableSectionHeader,
            owner.CallerSectionHeader,
            owner.TargetSectionHeader,
            adrp,
            add,
            owner.TargetSourceRange,
            targetIdentity,
            owner.TargetOutputRange,
            owner.MappingPolicy);

    private static byte[] RemoveAddressMapEntry(byte[] canonicalBytes, SemanticEntityId identity)
    {
        const int headerSize = 36;
        const int digestSize = 32;
        if (canonicalBytes.Length < headerSize + digestSize)
        {
            throw new InvalidOperationException("The source semantic snapshot is truncated.");
        }

        var entryCount = BinaryPrimitives.ReadUInt32LittleEndian(canonicalBytes.AsSpan(16, sizeof(uint)));
        var cursor = headerSize;
        for (var index = 0; index < entryCount; index++)
        {
            var entryStart = cursor;
            var kind = (SemanticEntityKind)canonicalBytes[cursor++];
            var identityLength = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(canonicalBytes.AsSpan(cursor, sizeof(uint))));
            cursor += sizeof(uint);
            var value = Encoding.UTF8.GetString(canonicalBytes, cursor, identityLength);
            cursor += identityLength;
            var outputIdentityPresent = canonicalBytes[cursor++];
            if (outputIdentityPresent == 1)
            {
                cursor = SkipEntityIdentity(canonicalBytes, cursor);
            }
            else if (outputIdentityPresent != 0)
            {
                throw new InvalidOperationException("The source semantic snapshot has a noncanonical optional identity flag.");
            }

            cursor = checked(cursor + (2 * 3 * sizeof(ulong)));
            if (kind != identity.Kind || !string.Equals(value, identity.Value, StringComparison.Ordinal))
            {
                continue;
            }

            var entryLength = cursor - entryStart;
            var mutated = new byte[canonicalBytes.Length - entryLength];
            Buffer.BlockCopy(canonicalBytes, 0, mutated, 0, entryStart);
            Buffer.BlockCopy(canonicalBytes, cursor, mutated, entryStart, canonicalBytes.Length - cursor);
            BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(12, sizeof(uint)), checked((uint)mutated.Length));
            BinaryPrimitives.WriteUInt32LittleEndian(mutated.AsSpan(16, sizeof(uint)), entryCount - 1);
            SHA256.HashData(mutated.AsSpan(0, mutated.Length - digestSize))
                .CopyTo(mutated.AsSpan(mutated.Length - digestSize));
            return mutated;
        }

        throw new InvalidOperationException($"The source semantic snapshot did not contain identity '{identity.Value}'.");
    }

    private static int SkipEntityIdentity(byte[] canonicalBytes, int cursor)
    {
        cursor = checked(cursor + 1); // entity kind
        var length = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(canonicalBytes.AsSpan(cursor, sizeof(uint))));
        return checked(cursor + sizeof(uint) + length);
    }

    private static byte[] ReplaceSnapshotAndRefreshDigests(
        byte[] artifactBytes,
        byte[] oldSnapshot,
        byte[] newSnapshot)
    {
        const int artifactDigestSize = 32;
        const int snapshotRecordPrefix = 8 + sizeof(uint) + 32;
        var snapshotOffset = FindSequence(artifactBytes, oldSnapshot);
        var recordStart = snapshotOffset - snapshotRecordPrefix;
        if (snapshotOffset < snapshotRecordPrefix
            || artifactBytes[recordStart] != (byte)ProtectedImageOperationCode.SemanticPlanSnapshot)
        {
            throw new InvalidOperationException("The Protected Image snapshot operation could not be located canonically.");
        }

        var oldRecordLength = BinaryPrimitives.ReadUInt32LittleEndian(artifactBytes.AsSpan(recordStart + 4, sizeof(uint)));
        var lengthDelta = oldSnapshot.Length - newSnapshot.Length;
        var refreshed = new byte[artifactBytes.Length - lengthDelta];
        Buffer.BlockCopy(artifactBytes, 0, refreshed, 0, snapshotOffset);
        Buffer.BlockCopy(newSnapshot, 0, refreshed, snapshotOffset, newSnapshot.Length);
        var oldSnapshotEnd = snapshotOffset + oldSnapshot.Length;
        var newSnapshotEnd = snapshotOffset + newSnapshot.Length;
        Buffer.BlockCopy(
            artifactBytes,
            oldSnapshotEnd,
            refreshed,
            newSnapshotEnd,
            artifactBytes.Length - oldSnapshotEnd);

        BinaryPrimitives.WriteUInt32LittleEndian(
            refreshed.AsSpan(12, sizeof(uint)),
            checked((uint)refreshed.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(
            refreshed.AsSpan(recordStart + 4, sizeof(uint)),
            checked((uint)(oldRecordLength - lengthDelta)));
        BinaryPrimitives.WriteUInt32LittleEndian(
            refreshed.AsSpan(recordStart + 8, sizeof(uint)),
            checked((uint)newSnapshot.Length));
        var snapshotDigest = Convert.FromHexString(SemanticPlanSnapshotCodec.ComputeSha256(newSnapshot));
        snapshotDigest.CopyTo(refreshed.AsSpan(recordStart + 12, snapshotDigest.Length));
        SHA256.HashData(refreshed.AsSpan(0, refreshed.Length - artifactDigestSize))
            .CopyTo(refreshed.AsSpan(refreshed.Length - artifactDigestSize));
        return refreshed;
    }

    private static int FindSequence(byte[] source, byte[] sequence)
    {
        for (var offset = 0; offset <= source.Length - sequence.Length; offset++)
        {
            if (source.AsSpan(offset, sequence.Length).SequenceEqual(sequence))
            {
                return offset;
            }
        }

        throw new InvalidOperationException("The requested snapshot bytes were not found in the Protected Image artifact.");
    }

    private static Scenario CreateScenario(byte[]? sourceOverride = null)
    {
        var source = sourceOverride ?? File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, FixturePath));
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, Describe(parsed.Diagnostics));
        var function = Assert.Single(parsed.File!.FunctionSymbols, symbol =>
            symbol.IsDynamic && symbol.Name == "urp_entry");
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
        Assert.True(emitted.IsSuccess, Describe(emitted.Diagnostics));
        var options = new RehydrationOptions(
            sourceHash,
            emitted.Role!.RequestSha256,
            UnitId,
            ProtectedImageProfile.HostContextEntry,
            ProducerId,
            ProducerBuild,
            ConsumerId,
            ConsumerBuild);
        return new Scenario(source, sourceHash, requestHash, emitted.ArtifactBytes!, options);
    }

    private static byte[] Mutate(byte[] input, ElfFile file, ElfFunctionSymbol function, string mutation)
    {
        var bytes = input.ToArray();
        var adrp = FindRelocation(file, function, ElfConstants.RArm64AdrPrelPgHi21);
        var add = FindRelocation(file, function, ElfConstants.RArm64AddAbsLo12Nc);
        var callbackSymbolOffset = GetSymbolOffset(file, adrp);
        var adrpAddress = adrp.Relocation.Offset;
        var addAddress = add.Relocation.Offset;
        var callAddress = checked(addAddress + (3UL * sizeof(uint)));
        switch (mutation)
        {
            case "without-sections":
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(40, sizeof(ulong)), 0);
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(58, sizeof(ushort)), 0);
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(60, sizeof(ushort)), 0);
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(62, sizeof(ushort)), 0);
                break;
            case "missing-relocation-row":
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(GetRelocationRowOffset(add), sizeof(ulong)),
                    checked(addAddress + sizeof(uint)));
                break;
            case "malformed-relocation-pair":
                // Duplicate the ADRP site: both exact relocation rows now claim one producer.
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(GetRelocationRowOffset(add), sizeof(ulong)),
                    adrpAddress);
                break;
            case "symbol-index":
            {
                var forgedSymbolIndex = checked(add.Relocation.SymbolIndex + 1);
                var forgedInfo = ((ulong)forgedSymbolIndex << 32) | add.Relocation.Type;
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(GetRelocationRowOffset(add) + 8, sizeof(ulong)),
                    forgedInfo);
                break;
            }
            case "sh-link":
            {
                var dynamicSymbolTableIndex = checked((uint)file.SectionHeaders
                    .Select((section, index) => (section, index))
                    .Single(item => item.section.Type == ElfConstants.ShtDynSym).index);
                WriteSectionHeaderUInt32(bytes, file, add.RelocationSectionIndex, 40, dynamicSymbolTableIndex);
                break;
            }
            case "sh-info":
            {
                var wrongTargetSection = checked((uint)file.SectionHeaders
                    .Select((section, index) => (section, index))
                    .Single(item => item.section.Type == ElfConstants.ShtDynSym).index);
                WriteSectionHeaderUInt32(bytes, file, add.RelocationSectionIndex, 44, wrongTargetSection);
                break;
            }
            case "relocation-type":
            {
                var forgedInfo = (add.Relocation.Info & 0xFFFFFFFF00000000UL)
                    | ElfConstants.RArm64AdrPrelPgHi21;
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(GetRelocationRowOffset(add) + 8, sizeof(ulong)),
                    forgedInfo);
                break;
            }
            case "addend":
                BinaryPrimitives.WriteInt64LittleEndian(
                    bytes.AsSpan(GetRelocationRowOffset(add) + 16, sizeof(long)),
                    1);
                break;
            case "target-owning-section":
            {
                var wrongSectionIndex = checked((ushort)file.SectionHeaders
                    .Select((section, index) => (section, index))
                    .First(item => item.index != adrp.Symbol!.SectionIndex
                        && item.section.Type != ElfConstants.ShtNobits).index);
                BinaryPrimitives.WriteUInt16LittleEndian(
                    bytes.AsSpan(callbackSymbolOffset + 6, sizeof(ushort)),
                    wrongSectionIndex);
                break;
            }
            case "non-function-target":
            {
                var info = bytes[callbackSymbolOffset + 4];
                bytes[callbackSymbolOffset + 4] = (byte)((info & 0xF0) | 1); // STT_OBJECT.
                break;
            }
            case "undefined-target":
                BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(callbackSymbolOffset + 6, sizeof(ushort)), 0);
                break;
            case "preemptible-target":
                bytes[callbackSymbolOffset + 4] = 0x12; // STB_GLOBAL | STT_FUNC.
                bytes[callbackSymbolOffset + 5] = 0; // STV_DEFAULT is preemptible.
                break;
            case "out-of-range-target":
            {
                // Keep the target VA inside the executable PT_LOAD, but let the
                // STT_FUNC range cross the owning .text section boundary.
                const ulong outOfRangeTarget = 0x264;
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(callbackSymbolOffset + 8, sizeof(ulong)),
                    outOfRangeTarget);
                var addWord = ReadInstruction(file, bytes, addAddress);
                var encodedAdd = (addWord & ~(0xFFFu << 10)) | (checked((uint)outOfRangeTarget) << 10);
                WriteInstruction(file, bytes, addAddress, encodedAdd);
                var loadHeader = Assert.Single(
                    file.ProgramHeaders.Select((header, index) => (header, index)),
                    item => item.header.Type == ElfConstants.PtLoad && item.header.IsExecutable);
                var headerOffset = checked((int)file.Header.ProgramHeaderOffset
                    + (loadHeader.index * file.Header.ProgramHeaderEntrySize));
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(headerOffset + 32, sizeof(ulong)), 0x26C);
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(headerOffset + 40, sizeof(ulong)), 0x26C);
                break;
            }
            case "unmapped-target":
                MakeCallbackMemoryOnly(bytes, file, function);
                break;
            case "changed-adrp-expression":
            {
                var original = ReadInstruction(file, bytes, adrpAddress);
                var encoded = new Aarch64InstructionEncoder().TryEncode(new Aarch64InstructionEncodeRequest(
                    original,
                    adrpAddress,
                    adrpAddress,
                    Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                    0x1000));
                Assert.True(encoded.IsSuccess, encoded.Diagnostic);
                WriteInstruction(file, bytes, adrpAddress, encoded.Encoding);
                break;
            }
            case "changed-add-expression":
            {
                var original = ReadInstruction(file, bytes, addAddress);
                WriteInstruction(file, bytes, addAddress, original + (1u << 10));
                break;
            }
            case "target-register-clobber":
            {
                var clobber = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
                    Aarch64InstructionEncodingFamily.MoveWideImmediate,
                    callAddress,
                    TargetOrImmediate: 0,
                    DestinationRegister: 1,
                    DestinationWidth: 64));
                Assert.True(clobber.IsSuccess, clobber.Diagnostic);
                WriteInstruction(file, bytes, callAddress, clobber.Encoding);
                WriteInstruction(file, bytes, checked(callAddress + sizeof(uint)), 0xD63F0020u); // BLR X1 after the clobber.
                break;
            }
            case "altered-stack-slot":
            {
                var loadAddress = checked(addAddress + (2UL * sizeof(uint)));
                var load = ReadInstruction(file, bytes, loadAddress);
                WriteInstruction(file, bytes, loadAddress, load + (1u << 10)); // LDR X1,[SP,#48] instead of #40.
                break;
            }
            case "conflicting-control-flow-branch":
            {
                var branchAddress = checked(function.Value + 12);
                WriteInstruction(file, bytes, branchAddress, 0x54000040u); // B.EQ +8 reaches ADD without the ADRP definition.
                break;
            }
            case "arbitrary-runtime-pointer":
                WriteInstruction(file, bytes, adrpAddress, 0xAA0003E1u); // MOV X1,X0: untrusted runtime argument.
                WriteInstruction(file, bytes, addAddress, 0xD503201Fu); // NOP; no static function address expression.
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        return bytes;
    }

    private static void AssertMutationReachedItsNamedBoundary(
        byte[] mutatedBytes,
        ElfFile file,
        ElfFunctionSymbol function,
        string mutation)
    {
        if (mutation is "out-of-range-target" or "unmapped-target")
        {
            var row = FindRelocation(file, function, ElfConstants.RArm64AdrPrelPgHi21);
            var symbol = Assert.IsType<ElfSectionSymbolIdentity>(row.Symbol);
            var section = file.SectionHeaders[symbol.SectionIndex];
            var inSection = symbol.Value >= section.Address
                && symbol.Value - section.Address <= section.Size
                && symbol.Size <= section.Size - (symbol.Value - section.Address);
            var mapped = file.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(symbol.Value),
                symbol.Size,
                out _);
            if (mutation == "out-of-range-target")
            {
                Assert.False(inSection, "the forged function range must cross its executable owning-section boundary");
                Assert.True(mapped, "the out-of-range control must remain inside a file-backed executable PT_LOAD");
            }
            else
            {
                Assert.True(inSection, "the unmapped target must retain a valid section-owned function range");
                Assert.False(mapped, "the callback bytes must not have a file-backed executable PT_LOAD mapping");
            }
        }
        else if (mutation == "target-register-clobber")
        {
            var call = FindRelocation(file, function, ElfConstants.RArm64AddAbsLo12Nc).Relocation.Offset + (3UL * sizeof(uint));
            var decoder = new AsmStoneAdapter();
            var clobber = decoder.Decode(ReadInstruction(file, mutatedBytes, call), call);
            var branch = decoder.Decode(ReadInstruction(file, mutatedBytes, call + sizeof(uint)), call + sizeof(uint));
            Assert.True(clobber.IsSuccess);
            Assert.Equal("MOVZ", clobber.Instruction!.Mnemonic.ToUpperInvariant());
            Assert.True(branch.IsSuccess);
            Assert.Equal("BLR", branch.Instruction!.Mnemonic.ToUpperInvariant());
            Assert.Contains(branch.Instruction.Operands, operand => operand.Register?.Index == 1);
        }
        else if (mutation == "altered-stack-slot")
        {
            var addAddress = FindRelocation(file, function, ElfConstants.RArm64AddAbsLo12Nc).Relocation.Offset;
            var load = new AsmStoneAdapter().Decode(ReadInstruction(file, mutatedBytes, addAddress + (2UL * sizeof(uint))), addAddress + (2UL * sizeof(uint)));
            Assert.True(load.IsSuccess);
            Assert.Contains(load.Instruction!.Operands, operand => operand.Memory?.Offset == 48);
        }
    }

    private static string ExpectedProofFailure(string mutation) => mutation switch
    {
        "without-sections" => "caller is not contained in one exact executable, file-backed source section",
        "missing-relocation-row" or "malformed-relocation-pair" or "sh-link" or "relocation-type" =>
            "lacks exactly one matching section-linked RELA row per site",
        "sh-info" or "symbol-index" or "addend" or "target-owning-section" or "non-function-target" or "undefined-target"
            or "preemptible-target" or "changed-adrp-expression" or "changed-add-expression" =>
            "does not identify one exact same-image, non-preemptible STT_FUNC symbol and section owner",
        "out-of-range-target" or "unmapped-target" => "executable section/file-range ownership is inconsistent",
        "target-register-clobber" => "BLR target is not loaded from a guarded HostContext callback",
        "arbitrary-runtime-pointer" => "BLR X1 target provenance is missing or conflicts across control-flow paths",
        "altered-stack-slot" => "does not preserve one exact ADRP/ADD expression through the same 64-bit stack slot",
        "conflicting-control-flow-branch" => "control-flow merge or a conflicting reaching definition",
        _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
    };

    private static ElfSectionRelocation FindRelocation(ElfFile file, ElfFunctionSymbol function, uint relocationType) =>
        Assert.Single(file.SectionRelocations, row =>
            row.Relocation.Offset >= function.Value
            && row.Relocation.Offset < function.End
            && row.Relocation.Type == relocationType);

    private static int GetRelocationRowOffset(ElfSectionRelocation row) =>
        checked((int)(row.RelocationSectionFileOffset.Value
            + row.RelocationSourceAddress.Value
            - row.RelocationSectionAddress.Value));

    private static int GetSymbolOffset(ElfFile file, ElfSectionRelocation row)
    {
        Assert.NotNull(row.Symbol);
        var table = file.SectionHeaders[checked((int)row.SymbolTableSectionIndex)];
        return checked((int)(table.Offset + ((ulong)row.Relocation.SymbolIndex * ElfConstants.SymbolEntrySize64)));
    }

    private static void WriteSectionHeaderUInt32(byte[] bytes, ElfFile file, int sectionIndex, int fieldOffset, uint value)
    {
        var headerOffset = checked((int)file.Header.SectionHeaderOffset
            + (sectionIndex * file.Header.SectionHeaderEntrySize)
            + fieldOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(headerOffset, sizeof(uint)), value);
    }

    private static uint ReadInstruction(ElfFile file, byte[] bytes, ulong address)
    {
        Assert.True(file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), sizeof(uint), out var offset));
        return BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(checked((int)offset.Value), sizeof(uint)));
    }

    private static void WriteInstruction(ElfFile file, byte[] bytes, ulong address, uint encoding)
    {
        Assert.True(file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), sizeof(uint), out var offset));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(checked((int)offset.Value), sizeof(uint)), encoding);
    }

    private static void MakeCallbackMemoryOnly(byte[] bytes, ElfFile file, ElfFunctionSymbol function)
    {
        var firstLoad = Assert.Single(
            file.ProgramHeaders.Select((header, index) => (header, index)),
            item => item.header.Type == ElfConstants.PtLoad && item.header.VirtualAddress == 0);
        var firstHeaderOffset = checked((int)file.Header.ProgramHeaderOffset
            + (firstLoad.index * file.Header.ProgramHeaderEntrySize));
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(firstHeaderOffset + 32, sizeof(ulong)), 0x1E0);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(firstHeaderOffset + 40, sizeof(ulong)), 0x1E8);

        var replacement = Assert.Single(
            file.ProgramHeaders.Select((header, index) => (header, index)),
            item => item.header.Type == ElfConstants.PtGnuStack);
        var replacementOffset = checked((int)file.Header.ProgramHeaderOffset
            + (replacement.index * file.Header.ProgramHeaderEntrySize));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(replacementOffset, sizeof(uint)), ElfConstants.PtLoad);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(replacementOffset + 4, sizeof(uint)), ElfConstants.PfR | ElfConstants.PfX);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(replacementOffset + 8, sizeof(ulong)), function.Value);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(replacementOffset + 16, sizeof(ulong)), function.Value);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(replacementOffset + 24, sizeof(ulong)), function.Value);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(replacementOffset + 32, sizeof(ulong)), 0x80);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(replacementOffset + 40, sizeof(ulong)), 0x80);
        BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(replacementOffset + 48, sizeof(ulong)), 1);
    }

    private static FunctionProtectionOptions CreateRequest(ElfFunctionSymbol function) =>
        new(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Dynamic, function.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening });

    private static ProtectedImageProducerOptions ProducerOptions(byte[] source, string requestHash) =>
        new(
            UnitId,
            ProtectedImageProfile.HostContextEntry,
            ProducerId,
            ProducerBuild,
            ConsumerId,
            Sha256(source),
            requestHash);

    private static ProtectedImageEmissionResult EmitProtectedImage(byte[] source, ElfFunctionSymbol function)
    {
        var request = CreateRequest(function);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        return new ProtectedImageProducer().Emit(source, request, ProducerOptions(source, requestHash));
    }

    private static byte[] ReencodeSnapshot(
        Scenario scenario,
        Func<SemanticPlanSnapshot, SemanticRewritePlan> mutate)
    {
        var image = ProtectedImageCodec.Decode(scenario.Artifact, scenario.SourceSha256, scenario.RequestSha256);
        Assert.True(image.IsSuccess, Describe(image.Diagnostics));
        var operation = Assert.Single(image.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, Describe(decoded.Diagnostics));
        var tamperedPlan = mutate(decoded.Snapshot!);
        var canonical = SemanticPlanSnapshotCodec.Create(tamperedPlan);
        Assert.True(canonical.IsSuccess, Describe(canonical.Diagnostics));
        var operations = image.Image.Operations.Select(candidate => candidate is ProtectedImageSemanticPlanSnapshot
            ? new ProtectedImageSemanticPlanSnapshot(canonical.Snapshot!)
            : candidate).ToArray();
        var encoded = ProtectedImageCodec.Encode(image.Image with { Operations = operations });
        Assert.True(encoded.IsSuccess, Describe(encoded.Diagnostics));
        return encoded.ArtifactBytes!;
    }

    private static void RefreshSnapshotDigest(byte[] bytes)
    {
        var digest = SHA256.HashData(bytes.AsSpan(0, bytes.Length - 32));
        digest.CopyTo(bytes.AsSpan(bytes.Length - 32));
    }

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static string Describe(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(Environment.NewLine, diagnostics);

    private sealed class RejectCallbackAdrpEncoder : IAarch64InstructionEncoder
    {
        private readonly IAarch64InstructionEncoder inner;
        private readonly ulong callbackAddress;

        public RejectCallbackAdrpEncoder(IAarch64InstructionEncoder inner, ulong callbackAddress)
        {
            this.inner = inner;
            this.callbackAddress = callbackAddress;
        }

        public bool Rejected { get; private set; }

        public Aarch64InstructionEncodeResult TryEncode(Aarch64InstructionEncodeRequest request)
        {
            if (request.Family == Aarch64InstructionEncodingFamily.AdrPrelPgHi21
                && request.TargetOrImmediate == callbackAddress)
            {
                Rejected = true;
                return Aarch64InstructionEncodeResult.Failure(
                    Aarch64InstructionEncodeDiagnosticCode.TargetOutOfRange,
                    "The test encoder rejected the emitted callback ADRP target as out of range.");
            }

            return inner.TryEncode(request);
        }

        public Aarch64InstructionEncodeResult TryCreate(Aarch64InstructionBuildRequest request) => inner.TryCreate(request);

        public Aarch64EncodeResult TryPermuteGeneralRegisters(
            uint encoding,
            ulong address,
            IReadOnlyDictionary<byte, byte> mapping) => inner.TryPermuteGeneralRegisters(encoding, address, mapping);
    }

    private sealed record Scenario(
        byte[] Source,
        string SourceSha256,
        string RequestSha256,
        byte[] Artifact,
        RehydrationOptions RehydrationOptions);
}
