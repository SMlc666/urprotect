using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.Application;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Integration;

public sealed class ExternalJumpTableProviderPublicationTests
{
    private const string ConsumerFixture = "Fixtures/ExternalJumpTable/liburprotect-external-table-consumer.so";
    private const string ProviderFixture = "Fixtures/ExternalJumpTable/liburprotect-jump-table-provider.so.1";
    private const string ProviderSoname = "liburprotect-jump-table-provider.so.1";
    private const string ProviderBuildId = "99ed42afaf9f2a6b87adebeffecb0ad95d4b5f66";
    private const string ProducerBuild = "1111111111111111111111111111111111111111111111111111111111111111";
    private const string ConsumerBuild = "2222222222222222222222222222222222222222222222222222222222222222";

    [Fact]
    public void ProviderSnapshotPublishesTypedConsumerProofAndRehydratesOnlyWithThePinnedProvider()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var options = ProducerOptions(source, request) with
        {
            ExternalJumpTableProviderInput = providerInput,
        };

        var emission = new ProtectedImageProducer().Emit(source, request, options);

        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));
        Assert.NotNull(emission.ArtifactBytes);
        var decodedArtifact = ProtectedImageCodec.Decode(
            emission.ArtifactBytes!,
            emission.Role!.SourceSha256,
            emission.Role.RequestSha256);
        Assert.True(decodedArtifact.IsSuccess, string.Join(Environment.NewLine, decodedArtifact.Diagnostics));
        var snapshotOperation = Assert.Single(
            decodedArtifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decodedSnapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(decodedSnapshot.IsSuccess, string.Join(Environment.NewLine, decodedSnapshot.Diagnostics));
        var providerExtension = Assert.Single(
            decodedSnapshot.Snapshot!.Extensions.OfType<SemanticExternalJumpTableExtension>());
        var consumerExtension = Assert.Single(
            decodedSnapshot.Snapshot.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>());
        Assert.Equal(providerExtension.TableIdentity, consumerExtension.ProviderTableIdentity);
        Assert.Equal(providerExtension.ProviderSha256, consumerExtension.ProviderSha256);
        Assert.Equal(ProviderSoname, providerExtension.ProviderSoname);
        Assert.Equal(ProviderBuildId, providerExtension.ProviderBuildIdHex);
        Assert.Equal(SHA256.HashData(providerBytes), Convert.FromHexString(providerExtension.ProviderSha256));
        Assert.Equal(4, providerExtension.Entries.Count);
        Assert.Equal(4, providerExtension.TargetSymbols.Count);
        Assert.DoesNotContain(providerPath, System.Text.Encoding.UTF8.GetString(emission.ArtifactBytes!));
        Assert.DoesNotContain(
            decodedSnapshot.Snapshot.AddressMap.Entries,
            entry => entry.Identity.Value == providerExtension.TableIdentity.Value);

        var rehydrationOptions = RehydrationOptions(source, emission.Role.RequestSha256) with
        {
            ExternalJumpTableProviderInput = providerInput,
        };
        var rehydrated = GenericRehydrationEngine.Rehydrate(
            source,
            emission.ArtifactBytes!,
            rehydrationOptions);
        Assert.True(rehydrated.IsSuccess, string.Join(Environment.NewLine, rehydrated.Diagnostics));
        Assert.NotNull(rehydrated.NativeImage);

        var missingProvider = GenericRehydrationEngine.Rehydrate(
            source,
            emission.ArtifactBytes!,
            rehydrationOptions with { ExternalJumpTableProviderInput = null });
        Assert.False(missingProvider.IsSuccess);
        Assert.Null(missingProvider.NativeImage);
        Assert.Contains(missingProvider.Diagnostics, diagnostic =>
            diagnostic.Message.Contains("requires matching trusted host provider input", StringComparison.Ordinal));

        var mismatchedProvider = GenericRehydrationEngine.Rehydrate(
            source,
            emission.ArtifactBytes!,
            rehydrationOptions with
            {
                ExternalJumpTableProviderInput = providerInput with { ExpectedSha256 = new string('0', 64) },
            });
        Assert.False(mismatchedProvider.IsSuccess);
        Assert.Null(mismatchedProvider.NativeImage);
        Assert.Contains(mismatchedProvider.Diagnostics, diagnostic =>
            diagnostic.Code is DiagnosticCode.OutputIdentityMismatch or DiagnosticCode.SemanticPlanSnapshotMalformed);
    }

    [Theory]
    [InlineData("relocation-owner")]
    [InlineData("got-permissions")]
    [InlineData("consumer-chain")]
    public void RehydrationRejectsSourceOwnerAndChainTamperingBeforeNativePublication(string mutation)
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));

        var artifactDecode = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(artifactDecode.IsSuccess, string.Join(Environment.NewLine, artifactDecode.Diagnostics));
        var snapshotOperation = Assert.Single(
            artifactDecode.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshotDecode = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(snapshotDecode.IsSuccess, string.Join(Environment.NewLine, snapshotDecode.Diagnostics));
        var storedProof = Assert.IsType<Aarch64ExternalJumpTableConsumerProof>(
            Assert.Single(snapshotDecode.Snapshot!.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>()).ConsumerProof);

        var mutatedSource = MutateSource(source, storedProof, mutation);
        var forgedDocument = artifactDecode.Image with { SourceSha256 = Sha256(mutatedSource) };
        var forgedArtifact = ProtectedImageCodec.Encode(forgedDocument);
        Assert.True(forgedArtifact.IsSuccess, string.Join(Environment.NewLine, forgedArtifact.Diagnostics));
        var result = GenericRehydrationEngine.Rehydrate(
            mutatedSource,
            forgedArtifact.ArtifactBytes!,
            RehydrationOptions(mutatedSource, emission.Role!.RequestSha256) with
            {
                ExternalJumpTableProviderInput = providerInput,
            });

        Assert.False(result.IsSuccess, mutation);
        Assert.Null(result.NativeImage);
    }

    [Fact]
    public void ChecksumRefreshedSnapshotRejectsAnIndirectCarrierWithTheWrongSourceInstructionIdentity()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with
            {
                ExternalJumpTableProviderInput = CreateProviderInput(providerPath, providerBytes),
            });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));

        var artifact = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));
        var operation = Assert.Single(artifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decoded = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var proof = Assert.Single(decoded.Snapshot!.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>()).ConsumerProof;
        var expectedIdentity = SemanticEntityId.Instruction(new VirtualAddress(proof.BranchAddress));
        var replacementIdentity = SemanticEntityId.Instruction(new VirtualAddress(proof.BranchAddress + sizeof(uint)));
        var originalString = EncodeSnapshotString(expectedIdentity.Value);
        var replacement = Encoding.UTF8.GetBytes(replacementIdentity.Value);
        Assert.Equal(originalString.Length - sizeof(uint), replacement.Length);

        var tampered = operation.CanonicalBytes.ToArray();
        var content = tampered.AsSpan(0, tampered.Length - 32);
        var sourceIdentityOffset = content.LastIndexOf(originalString);
        Assert.True(sourceIdentityOffset >= 0);
        Assert.True(content.IndexOf(originalString) < sourceIdentityOffset);
        replacement.CopyTo(content.Slice(sourceIdentityOffset + sizeof(uint), replacement.Length));
        RefreshSnapshotDigest(tampered);

        var result = SemanticPlanSnapshotCodec.Decode(tampered);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Snapshot);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("branch-identity", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("soname")]
    [InlineData("build-id")]
    [InlineData("sha256")]
    public void ProducerRejectsEveryProviderIdentityPinMismatchWithoutAnArtifact(string identity)
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        providerInput = identity switch
        {
            "soname" => providerInput with { ExpectedSoname = "libwrong-provider.so" },
            "build-id" => providerInput with { ExpectedBuildIdHex = new string('a', 40) },
            "sha256" => providerInput with { ExpectedSha256 = new string('0', 64) },
            _ => throw new ArgumentOutOfRangeException(nameof(identity), identity, "Unknown provider identity mutation."),
        };
        var request = Request();

        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });

        Assert.False(emission.IsSuccess, identity);
        Assert.Null(emission.ArtifactBytes);
        Assert.Null(emission.Role);
        Assert.NotEmpty(emission.Diagnostics);
    }

    [Fact]
    public void ProviderTargetNameSwapsCannotBePublishedWithoutMatchingEntryOrder()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with
            {
                ExternalJumpTableProviderInput = CreateProviderInput(providerPath, providerBytes),
            });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));

        var decoded = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var operation = Assert.Single(decoded.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshot = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(snapshot.IsSuccess, string.Join(Environment.NewLine, snapshot.Diagnostics));
        var plan = snapshot.Snapshot!.Plan;
        var providerExtension = Assert.Single(plan.Extensions.OfType<SemanticExternalJumpTableExtension>());
        var targets = providerExtension.TargetSymbols.ToArray();
        var firstTargetName = targets[0].Name;
        targets[0] = targets[0] with { Name = targets[1].Name };
        targets[1] = targets[1] with { Name = firstTargetName };
        var mismatchedProvider = new SemanticExternalJumpTableExtension(
            providerExtension.TableIdentity,
            providerExtension.ProviderSoname,
            providerExtension.ProviderBuildIdHex,
            providerExtension.ProviderSha256,
            providerExtension.ProviderFileSize,
            providerExtension.TableObject,
            targets,
            providerExtension.Entries,
            providerExtension.TableBytes,
            providerExtension.Encoding);
        var extensions = plan.Extensions
            .Select(extension => ReferenceEquals(extension, providerExtension) ? mismatchedProvider : extension)
            .ToArray();

        var result = SemanticPlanSnapshotCodec.Create(new SemanticRewritePlan(
            plan.AddressMap,
            plan.Instructions,
            plan.Fixups,
            extensions,
            plan.Diagnostics));

        Assert.False(result.IsSuccess);
        Assert.Null(result.Snapshot);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("exact provider identity", StringComparison.Ordinal));
    }

    [Fact]
    public void DuplicateExternalSemanticOwnersCannotBePublished()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));
        var decoded = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var operation = Assert.Single(decoded.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshot = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
        Assert.True(snapshot.IsSuccess, string.Join(Environment.NewLine, snapshot.Diagnostics));
        var plan = snapshot.Snapshot!.Plan;
        var providerExtension = Assert.Single(plan.Extensions.OfType<SemanticExternalJumpTableExtension>());

        var duplicate = SemanticPlanSnapshotCodec.Create(new SemanticRewritePlan(
            plan.AddressMap,
            plan.Instructions,
            plan.Fixups,
            plan.Extensions.Append(providerExtension),
            plan.Diagnostics));

        Assert.False(duplicate.IsSuccess);
        Assert.Null(duplicate.Snapshot);
        Assert.Contains(duplicate.Diagnostics, diagnostic =>
            diagnostic.Message.Contains("may be carried only once", StringComparison.Ordinal));
    }

    [Fact]
    public void ExternalGotPageEncodingFailureDoesNotPublishAProtectedImage()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var baseline = new ProtectedImageProducer().Emit(source, request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });
        Assert.True(baseline.IsSuccess, string.Join(Environment.NewLine, baseline.Diagnostics));
        var decoded = ProtectedImageCodec.Decode(baseline.ArtifactBytes!);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var snapshotOperation = Assert.Single(decoded.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(snapshot.IsSuccess, string.Join(Environment.NewLine, snapshot.Diagnostics));
        var proof = Assert.IsType<Aarch64ExternalJumpTableConsumerProof>(
            Assert.Single(snapshot.Snapshot!.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>()).ConsumerProof);
        var rejectingEncoder = new RejectExternalGotPageEncoder(
            new Aarch64InstructionEncoder(),
            proof.GotSlotAddress.Value & ~0xFFFUL);
        var producer = new ProtectedImageProducer(new ProtectionWorkflow(
            new FunctionProtectionService(encoder: rejectingEncoder)));

        var emission = producer.Emit(source, request, ProducerOptions(source, request) with
        {
            ExternalJumpTableProviderInput = providerInput,
        });

        Assert.True(rejectingEncoder.Rejected);
        Assert.False(emission.IsSuccess);
        Assert.Null(emission.ArtifactBytes);
        Assert.Null(emission.Role);
    }

    [Fact]
    public void RehydrationRejectsAnExternalProviderSnapshotWithoutItsSemanticConsumerOwner()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));

        var decodedArtifact = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(decodedArtifact.IsSuccess, string.Join(Environment.NewLine, decodedArtifact.Diagnostics));
        var snapshotOperation = Assert.Single(
            decodedArtifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(snapshot.IsSuccess, string.Join(Environment.NewLine, snapshot.Diagnostics));
        var plan = snapshot.Snapshot!.Plan;
        var missingOwnerExtensions = plan.Extensions
            .Where(extension => extension is not SemanticExternalJumpTableConsumerExtension)
            .ToArray();
        var missingOwnerSnapshot = SemanticPlanSnapshotCodec.Create(new SemanticRewritePlan(
            plan.AddressMap,
            plan.Instructions,
            plan.Fixups,
            missingOwnerExtensions,
            plan.Diagnostics));
        Assert.True(missingOwnerSnapshot.IsSuccess, string.Join(Environment.NewLine, missingOwnerSnapshot.Diagnostics));
        var operations = decodedArtifact.Image.Operations
            .Select(operation => operation is ProtectedImageSemanticPlanSnapshot
                ? new ProtectedImageSemanticPlanSnapshot(missingOwnerSnapshot.Snapshot!)
                : operation)
            .ToArray();
        var missingOwnerArtifact = ProtectedImageCodec.Encode(decodedArtifact.Image with { Operations = operations });
        Assert.True(missingOwnerArtifact.IsSuccess, string.Join(Environment.NewLine, missingOwnerArtifact.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            source,
            missingOwnerArtifact.ArtifactBytes!,
            RehydrationOptions(source, emission.Role!.RequestSha256) with
            {
                ExternalJumpTableProviderInput = providerInput,
            });

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.NotEmpty(result.Diagnostics);
    }

    [Fact]
    public void RehydrationRejectsAnExternalGotPageFixupThatNoLongerTargetsItsProvenGotSlot()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));

        var decodedArtifact = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(decodedArtifact.IsSuccess, string.Join(Environment.NewLine, decodedArtifact.Diagnostics));
        var snapshotOperation = Assert.Single(
            decodedArtifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var decodedSnapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(decodedSnapshot.IsSuccess, string.Join(Environment.NewLine, decodedSnapshot.Diagnostics));
        var plan = decodedSnapshot.Snapshot!.Plan;
        var proof = Assert.Single(
            plan.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>()).ConsumerProof;
        var producer = plan.Instructions.Single(instruction =>
            instruction.SourceVirtualAddress.Value == proof.GotPageProducerAddress);
        var wrongTarget = SemanticTarget.Exact(
            SemanticEntityId.Instruction(new VirtualAddress(proof.BranchAddress)),
            new VirtualAddress(proof.BranchAddress));
        var references = producer.References.Select(reference => reference with
        {
            Target = wrongTarget,
            PcRelative = reference.PcRelative is { } relative ? relative with { Target = wrongTarget } : null,
        }).ToArray();
        var changedProducer = new SemanticInstruction(
            producer.SourceVirtualAddress,
            producer.SourceFileOffset,
            producer.Encoding,
            producer.Mnemonic,
            producer.SourceRange,
            producer.Operands,
            producer.RegisterEffects,
            producer.FlagEffects,
            producer.ControlFlow,
            producer.ControlFlowTarget,
            producer.PcRelativeExpression is { } expression ? expression with { Target = wrongTarget } : null,
            producer.LiteralReference,
            producer.Relocations,
            references,
            producer.OpaquePreservation);
        var instructions = plan.Instructions.Select(instruction =>
            instruction.SourceVirtualAddress == producer.SourceVirtualAddress ? changedProducer : instruction).ToArray();
        var fixups = plan.Fixups.Select(fixup => fixup.SourceAddress.Value == proof.GotPageProducerAddress
            ? new SemanticFixup(
                fixup.Kind,
                fixup.SourceAddress,
                fixup.SourceFileOffset,
                fixup.OriginalEncoding,
                wrongTarget,
                fixup.SourceRange,
                fixup.Expression is { } expression ? expression with { Target = wrongTarget } : null,
                fixup.Relocation,
                fixup.Relaxation,
                fixup.RelaxationOptions)
            : fixup).ToArray();
        var tamperedSnapshot = SemanticPlanSnapshotCodec.Create(new SemanticRewritePlan(
            plan.AddressMap,
            instructions,
            fixups,
            plan.Extensions,
            plan.Diagnostics));
        Assert.True(tamperedSnapshot.IsSuccess, string.Join(Environment.NewLine, tamperedSnapshot.Diagnostics));
        var operations = decodedArtifact.Image.Operations.Select(operation =>
            operation is ProtectedImageSemanticPlanSnapshot
                ? new ProtectedImageSemanticPlanSnapshot(tamperedSnapshot.Snapshot!)
                : operation).ToArray();
        var tamperedArtifact = ProtectedImageCodec.Encode(decodedArtifact.Image with { Operations = operations });
        Assert.True(tamperedArtifact.IsSuccess, string.Join(Environment.NewLine, tamperedArtifact.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            source,
            tamperedArtifact.ArtifactBytes!,
            RehydrationOptions(source, emission.Role!.RequestSha256) with
            {
                ExternalJumpTableProviderInput = providerInput,
            });

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
    }

    [Theory]
    [InlineData("target-only")]
    [InlineData("target-identity")]
    [InlineData("expression-target")]
    [InlineData("expression-place")]
    [InlineData("expression-scale")]
    [InlineData("expression-page")]
    [InlineData("expression-addend")]
    [InlineData("source-address-range")]
    [InlineData("source-file-range")]
    [InlineData("original-encoding")]
    [InlineData("kind")]
    [InlineData("relaxation")]
    [InlineData("missing")]
    [InlineData("duplicate")]
    [InlineData("conflicting-load-fixup")]
    public void ProducerFixupForgeriesAreRejectedAtTheNearestPublicationOwner(string mutation)
    {
        using var scenario = new PublicationScenario();
        var plan = scenario.Snapshot.Plan;
        var fixup = Assert.Single(plan.Fixups, candidate => candidate.SourceAddress.Value == scenario.Proof.GotPageProducerAddress);
        var kind = fixup.Kind;
        var address = fixup.SourceAddress;
        var offset = fixup.SourceFileOffset;
        var range = fixup.SourceRange;
        var encoding = fixup.OriginalEncoding;
        var target = fixup.Target;
        var expression = fixup.Expression!;
        var relaxation = fixup.Relaxation;
        var wrongTarget = SemanticTarget.Exact(new VirtualAddress(scenario.Proof.BranchAddress));
        switch (mutation)
        {
            case "target-only":
                target = wrongTarget;
                break;
            case "target-identity":
                target = SemanticTarget.Exact(SemanticEntityId.Instruction(new VirtualAddress(scenario.Proof.BranchAddress)), target.SourceAddress);
                expression = expression with { Target = target };
                break;
            case "expression-target":
                expression = expression with { Target = wrongTarget };
                break;
            case "expression-place":
                expression = expression with { Place = new VirtualAddress(scenario.Proof.GotLoadProducerAddress) };
                break;
            case "expression-scale":
                expression = expression with { Scale = expression.Scale + 1 };
                break;
            case "expression-page":
                expression = expression with { IsPageRelative = !expression.IsPageRelative };
                break;
            case "expression-addend":
                expression = expression with { Addend = 0x1000 };
                break;
            case "source-address-range":
                address = new VirtualAddress(scenario.Proof.GotLoadProducerAddress);
                range = range with { VirtualAddress = address };
                break;
            case "source-file-range":
                offset = new FileOffset(offset.Value + sizeof(uint));
                range = range with { FileOffset = offset };
                break;
            case "original-encoding":
                var changed = new Aarch64InstructionEncoder().TryEncode(new Aarch64InstructionEncodeRequest(
                    encoding, address.Value, address.Value, Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                    (scenario.Proof.GotSlotAddress.Value & ~0xFFFUL) + 0x1000));
                Assert.True(changed.IsSuccess, changed.Diagnostic);
                encoding = changed.Encoding;
                break;
            case "kind":
                kind = SemanticFixupKind.AdrPrelLo21;
                expression = expression with { Kind = PcRelativeExpressionKind.AdrPrelLo21 };
                break;
            case "relaxation":
                relaxation = SemanticRelaxationKind.NearVeneer;
                break;
            case "conflicting-load-fixup":
                address = new VirtualAddress(scenario.Proof.GotLoadProducerAddress);
                offset = new FileOffset(offset.Value + sizeof(uint));
                range = new SemanticSourceRange(offset, address, sizeof(uint));
                expression = expression with { Place = address };
                break;
            case "missing":
            case "duplicate":
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation));
        }

        var changedFixup = new SemanticFixup(kind, address, offset, encoding, target, range, expression,
            fixup.Relocation, relaxation, fixup.RelaxationOptions);
        var fixups = mutation switch
        {
            "missing" => plan.Fixups.Where(candidate => candidate != fixup),
            "duplicate" => plan.Fixups.Append(fixup),
            "conflicting-load-fixup" => plan.Fixups.Append(changedFixup),
            _ => plan.Fixups.Select(candidate => candidate == fixup ? changedFixup : candidate),
        };
        var forgedPlan = new SemanticRewritePlan(plan.AddressMap, plan.Instructions, fixups, plan.Extensions, plan.Diagnostics);
        if (mutation is "target-only" or "expression-target" or "expression-scale" or "expression-page"
            or "kind" or "duplicate" or "missing" or "source-address-range")
        {
            // These malformed assertions cannot even be serialized by the existing
            // semantic owner. Keep that nearest gate rather than manufacturing a
            // second snapshot writer just to get them to rehydration.
            var rejected = SemanticPlanSnapshotCodec.Create(forgedPlan);
            Assert.False(rejected.IsSuccess);
            Assert.Null(rejected.Snapshot);
            Assert.Contains(rejected.Diagnostics, diagnostic => diagnostic.Code is
                DiagnosticCode.SemanticPlanMalformed or DiagnosticCode.SemanticFixupMalformed);
            return;
        }

        var artifact = scenario.Encode(forgedPlan);
        var result = scenario.Rehydrate(artifact);

        Assert.False(result.IsSuccess, mutation);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("source-derived projection", StringComparison.Ordinal));
    }

    [Fact]
    public void RehydrationRejectsAProducerInstructionAndFixupOmittedTogetherWithRefreshedChecksums()
    {
        using var scenario = new PublicationScenario();
        var plan = scenario.Snapshot.Plan;
        var address = scenario.Proof.GotPageProducerAddress;
        var artifact = scenario.Encode(new SemanticRewritePlan(plan.AddressMap,
            plan.Instructions.Where(instruction => instruction.SourceVirtualAddress.Value != address),
            plan.Fixups.Where(fixup => fixup.SourceAddress.Value != address), plan.Extensions, plan.Diagnostics));

        var result = scenario.Rehydrate(artifact);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("source-derived projection", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void RehydrationRejectsASelfConsistentProducerMapPointingAtAnAppendedDeadChain(bool removeLiveBranch)
    {
        using var scenario = new PublicationScenario();
        var plan = scenario.Snapshot.Plan;
        var function = Assert.Single(plan.AddressMap.Functions);
        var region = Assert.Single(scenario.Document.Operations.OfType<ProtectedImageEmitRegion>());
        var code = new byte[region.CodeBytes.Length + (5 * sizeof(uint))];
        region.CodeBytes.CopyTo(code, 0);
        var entries = plan.AddressMap.Entries.ToArray();
        for (var index = 0; index < scenario.Proof.ProducerAddresses.Count; index++)
        {
            var id = SemanticEntityId.Instruction(new VirtualAddress(scenario.Proof.ProducerAddresses[index]));
            Assert.True(plan.AddressMap.TryGet(id, out var row));
            var offset = checked((int)(row.OutputRange.VirtualAddress.Value - function.OutputRange.VirtualAddress.Value));
            var appendedOffset = region.CodeBytes.Length + (index * sizeof(uint));
            var appendedAddress = function.OutputRange.VirtualAddress.Value + (ulong)appendedOffset;
            var word = BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(offset, sizeof(uint)));
            if (index == 0)
            {
                var encodedPage = new Aarch64InstructionEncoder().TryEncode(new Aarch64InstructionEncodeRequest(
                    word, row.OutputRange.VirtualAddress.Value, appendedAddress, Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                    scenario.Proof.GotSlotAddress.Value & ~0xFFFUL));
                Assert.True(encodedPage.IsSuccess, encodedPage.Diagnostic);
                word = encodedPage.Encoding;
            }

            BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(appendedOffset, sizeof(uint)), word);
            if (removeLiveBranch && index == scenario.Proof.ProducerAddresses.Count - 1)
            {
                var replaced = new Aarch64InstructionEncoder().TryCreate(new Aarch64InstructionBuildRequest(
                    Aarch64InstructionEncodingFamily.Return, row.OutputRange.VirtualAddress.Value, 0));
                Assert.True(replaced.IsSuccess, replaced.Diagnostic);
                BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(offset, sizeof(uint)), replaced.Encoding);
            }

            entries = entries.Select(entry => entry.Identity == id ? entry with
            {
                OutputRange = new SemanticSourceRange(
                    new FileOffset(function.OutputRange.FileOffset.Value + (ulong)appendedOffset),
                    new VirtualAddress(appendedAddress), sizeof(uint)),
            } : entry).ToArray();
        }

        entries = entries.Select(entry => entry.Identity == function.Identity ? entry with
        {
            OutputRange = entry.OutputRange with { Size = (ulong)code.Length },
        } : entry).ToArray();
        var map = AddressMap.Create(entries);
        Assert.True(map.IsSuccess, string.Join(Environment.NewLine, map.Diagnostics));
        var encoded = scenario.Encode(new SemanticRewritePlan(map.Map!, plan.Instructions, plan.Fixups, plan.Extensions, plan.Diagnostics));
        var decoded = ProtectedImageCodec.Decode(encoded);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var artifact = ProtectedImageCodec.Encode(decoded.Image! with
        {
            Operations = decoded.Image!.Operations.Select(operation => operation is ProtectedImageEmitRegion emitted
                ? new ProtectedImageEmitRegion(emitted.RegionId, emitted.SourceAddress, emitted.SourceSize, code) : operation).ToArray(),
        });
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));

        var result = scenario.Rehydrate(artifact.ArtifactBytes!);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("final external consumer instruction/reference chain", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("page-output-address")]
    [InlineData("got-output-address")]
    [InlineData("got-source-file")]
    [InlineData("missing-page")]
    [InlineData("missing-got")]
    [InlineData("missing-producer")]
    [InlineData("producer-output-file")]
    [InlineData("producer-source-file")]
    public void RehydrationRejectsChecksumRefreshedConsumerMappingForgeries(string mutation)
    {
        using var scenario = new PublicationScenario();
        var plan = scenario.Snapshot.Plan;
        var pageAddress = scenario.Proof.GotSlotAddress.Value & ~0xFFFUL;
        var page = Assert.Single(plan.AddressMap.Entries, entry => entry.Identity.Kind == SemanticEntityKind.RelocationTarget
            && entry.SourceRange.VirtualAddress.Value == pageAddress);
        var got = Assert.Single(plan.AddressMap.Entries, entry => entry.Identity.Kind == SemanticEntityKind.RelocationTarget
            && entry.SourceRange.VirtualAddress == scenario.Proof.GotSlotAddress);
        Assert.True(plan.AddressMap.TryGet(SemanticEntityId.Instruction(new VirtualAddress(scenario.Proof.GotPageProducerAddress)), out var producer));
        var entries = plan.AddressMap.Entries.ToArray();
        var selected = mutation switch
        {
            "page-output-address" or "missing-page" => page,
            "got-output-address" or "got-source-file" or "missing-got" => got,
            _ => producer,
        };
        var changed = mutation switch
        {
            "page-output-address" or "got-output-address" => selected with
            {
                OutputRange = selected.OutputRange with { VirtualAddress = new VirtualAddress(selected.OutputRange.VirtualAddress.Value + 0x100000) },
            },
            "got-source-file" => selected with
            {
                SourceRange = selected.SourceRange with { FileOffset = new FileOffset(selected.SourceRange.FileOffset.Value + 0x100000) },
                OutputRange = selected.OutputRange with { FileOffset = new FileOffset(selected.OutputRange.FileOffset.Value + 0x100000) },
            },
            "producer-output-file" => selected with
            {
                OutputRange = selected.OutputRange with { FileOffset = new FileOffset(selected.OutputRange.FileOffset.Value + 0x100000) },
            },
            "producer-source-file" => selected with
            {
                SourceRange = selected.SourceRange with { FileOffset = new FileOffset(selected.SourceRange.FileOffset.Value + 0x100000) },
            },
            _ => selected,
        };
        var map = AddressMap.Create(mutation.StartsWith("missing-", StringComparison.Ordinal)
            ? entries.Where(entry => entry != selected)
            : entries.Select(entry => entry == selected ? changed : entry));
        Assert.True(map.IsSuccess, string.Join(Environment.NewLine, map.Diagnostics));
        var artifact = scenario.Encode(new SemanticRewritePlan(map.Map!, plan.Instructions, plan.Fixups, plan.Extensions, plan.Diagnostics));
        var result = scenario.Rehydrate(artifact);

        Assert.False(result.IsSuccess, mutation);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("GOT output mapping", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("adrp")]
    [InlineData("got-load")]
    [InlineData("indexed-load")]
    [InlineData("add")]
    [InlineData("branch")]
    public void RehydrationRejectsChecksumRefreshedEmittedProducerChainForgeries(string mutation)
    {
        using var scenario = new PublicationScenario();
        var region = Assert.Single(scenario.Document.Operations.OfType<ProtectedImageEmitRegion>());
        var function = Assert.Single(scenario.Snapshot.AddressMap.Functions);
        var ordinal = ChainOrdinal(mutation);
        Assert.True(scenario.Snapshot.AddressMap.TryGet(
            SemanticEntityId.Instruction(new VirtualAddress(scenario.Proof.ProducerAddresses[ordinal])), out var row));
        var offset = checked((int)(row.OutputRange.VirtualAddress.Value - function.OutputRange.VirtualAddress.Value));
        var code = region.CodeBytes.ToArray();
        var word = BinaryPrimitives.ReadUInt32LittleEndian(code.AsSpan(offset, sizeof(uint)));
        var changedWord = ChangeChainWord(word, row.OutputRange.VirtualAddress.Value, scenario.Proof, mutation);
        BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(offset, sizeof(uint)), changedWord);
        var changedRegion = new ProtectedImageEmitRegion(region.RegionId, region.SourceAddress, region.SourceSize, code);
        var encoded = ProtectedImageCodec.Encode(scenario.Document with
        {
            Operations = scenario.Document.Operations.Select(operation => ReferenceEquals(operation, region) ? changedRegion : operation).ToArray(),
        });
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));
        var result = scenario.Rehydrate(encoded.ArtifactBytes!);

        Assert.False(result.IsSuccess, mutation);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains("GOT output mapping", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("adrp")]
    [InlineData("got-load")]
    [InlineData("indexed-load")]
    [InlineData("add")]
    [InlineData("branch")]
    [InlineData("got-owner")]
    [InlineData("got-bytes")]
    [InlineData("dynsym-owner")]
    [InlineData("needed-provider")]
    [InlineData("entry-symbol")]
    [InlineData("entry-mapping")]
    [InlineData("dispatcher-entry")]
    [InlineData("bounds-compare")]
    [InlineData("bounds-branch")]
    [InlineData("safe-default")]
    public void FinalExternalConsumerValidatorRejectsActualOutputForgeriesIndependentlyOfTheSnapshot(string mutation)
    {
        using var scenario = new PublicationScenario();
        var baseline = scenario.Rehydrate(scenario.Artifact);
        Assert.True(baseline.IsSuccess, string.Join(Environment.NewLine, baseline.Diagnostics));
        var regions = scenario.Document.Operations.OfType<ProtectedImageEmitRegion>().Select(region => new ElfLayoutRegionRequest(
            $"region:{region.RegionId:D10}", $"region:{region.RegionId:D10}", region.SourceAddress, region.SourceSize, region.CodeBytes));
        var branches = scenario.Document.Operations.OfType<ProtectedImageEntryBranchFixup>().Select(fixup => new ElfLayoutBranchRequest(
            $"entry:{fixup.SourceRegionId}:{fixup.SourceOffset}", $"region:{fixup.SourceRegionId:D10}", $"region:{fixup.TargetRegionId:D10}",
            fixup.SourceAddress, fixup.SourceOffset, fixup.TargetOffset));
        var planned = ElfLayoutPlanner.Plan(scenario.Source, scenario.SourceFile, regions, branches);
        Assert.True(planned.IsSuccess, string.Join(Environment.NewLine, planned.Diagnostics));
        Assert.Equal(baseline.NativeImage!.LayoutEvidence!.AddressMap, planned.Plan!.AddressMap);
        var validDiagnostics = new DiagnosticBag();
        Assert.True(SemanticExternalJumpTablePublicationValidator.ValidateSourceAndProvider(
            scenario.SourceFile, scenario.Document, scenario.Snapshot, scenario.ProviderInput, validDiagnostics, out var validatedAnalysis),
            string.Join(Environment.NewLine, validDiagnostics));
        Assert.NotNull(validatedAnalysis);
        Assert.True(SemanticExternalJumpTablePublicationValidator.ValidateRehydratedImage(
            scenario.SourceFile, baseline.NativeImage.ParsedImage, planned.Plan, scenario.Snapshot, validatedAnalysis, validDiagnostics),
            string.Join(Environment.NewLine, validDiagnostics));

        var bytes = baseline.NativeImage.Bytes.ToArray();
        var output = baseline.NativeImage.ParsedImage;
        if (mutation == "needed-provider")
        {
            var dynamic = Assert.Single(output.ProgramHeaders, header => header.Type == ElfConstants.PtDynamic);
            var neededIndex = output.DynamicEntries.ToList().FindIndex(entry => entry.Tag == ElfConstants.DtNeeded);
            Assert.True(neededIndex >= 0);
            var offset = checked((int)(dynamic.Offset + ((ulong)neededIndex * 16) + 8));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset, sizeof(ulong)),
                output.DynamicSymbols[checked((int)scenario.Proof.ImportOwner.SymbolIndex)].Name);
        }
        else if (mutation is "dynsym-owner" or "entry-symbol")
        {
            var tableAddress = Assert.Single(output.DynamicEntries, entry => entry.Tag == ElfConstants.DtSymTab).Value;
            var symbolIndex = mutation == "entry-symbol"
                ? scenario.Proof.SelectedFunction.TableIndex : scenario.Proof.ImportOwner.SymbolIndex;
            var symbolAddress = tableAddress + (symbolIndex * ElfConstants.SymbolEntrySize64);
            Assert.True(output.LoadMap.TryVirtualAddressToFileOffset(
                new VirtualAddress(symbolAddress), ElfConstants.SymbolEntrySize64, out var symbolOffset));
            var fieldOffset = checked((int)symbolOffset.Value + (mutation == "entry-symbol" ? 8 : 16));
            var original = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(fieldOffset, sizeof(ulong)));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(fieldOffset, sizeof(ulong)), original + sizeof(uint));
        }
        else if (mutation is "got-owner" or "got-bytes")
        {
            if (mutation == "got-owner")
            {
                var relaOffset = scenario.Proof.ImportOwner.Relocation.SourceAddress;
                BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(checked((int)relaOffset + sizeof(ulong)), sizeof(ulong)),
                    ((ulong)scenario.Proof.ImportOwner.SymbolIndex << 32) | ElfConstants.RArm64JumpSlot);
            }
            else
            {
                bytes[checked((int)scenario.Proof.GotSlotFileOffset.Value)] ^= 1;
            }
        }
        else
        {
            var function = Assert.Single(scenario.Snapshot.AddressMap.Functions);
            var placement = Assert.Single(planned.Plan.AddressMap, entry => entry.SourceRange is { } range
                && range.VirtualAddress == function.SourceRange.VirtualAddress && range.Size == function.SourceRange.Size);
            var sourceAddress = mutation switch
            {
                "bounds-compare" => scenario.Proof.CompareAddress,
                "bounds-branch" => scenario.Proof.BoundsBranchAddress,
                "safe-default" => scenario.Proof.SafeDefaultAddress,
                "entry-mapping" or "dispatcher-entry" => scenario.Proof.GotPageProducerAddress,
                _ => scenario.Proof.ProducerAddresses[ChainOrdinal(mutation)],
            };
            Assert.True(scenario.Snapshot.AddressMap.TryGet(
                SemanticEntityId.Instruction(new VirtualAddress(sourceAddress)), out var row));
            var address = mutation == "entry-mapping" ? scenario.Proof.SelectedFunction.Value
                : mutation == "dispatcher-entry" ? placement.OutputRange.VirtualAddress.Value
                : placement.OutputRange.VirtualAddress.Value + row.OutputRange.VirtualAddress.Value - function.OutputRange.VirtualAddress.Value;
            Assert.True(output.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(address), sizeof(uint), out var fileOffset));
            var word = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(checked((int)fileOffset.Value), sizeof(uint)));
            var changed = mutation == "entry-mapping"
                ? new Aarch64InstructionEncoder().TryEncode(new Aarch64InstructionEncodeRequest(
                    word, address, address, Aarch64InstructionEncodingFamily.Branch26, placement.OutputRange.VirtualAddress.Value + sizeof(uint)))
                : default;
            var changedWord = mutation switch
            {
                "entry-mapping" => changed.Encoding,
                "dispatcher-entry" or "bounds-compare" or "bounds-branch" or "safe-default" =>
                    scenario.Snapshot.Plan.Instructions.Single(instruction =>
                        instruction.SourceVirtualAddress.Value == scenario.Proof.SafeDefaultPathAddresses[^1]).Encoding,
                _ => ChangeChainWord(word, address, scenario.Proof, mutation),
            };
            Assert.NotEqual(word, changedWord);
            Assert.True(mutation != "entry-mapping" || changed.IsSuccess, changed.Diagnostic);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(checked((int)fileOffset.Value), sizeof(uint)), changedWord);
        }

        var parsed = ElfParser.Parse(bytes);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var diagnostics = new DiagnosticBag();
        var valid = SemanticExternalJumpTablePublicationValidator.ValidateRehydratedImage(
            scenario.SourceFile, parsed.File!, planned.Plan, scenario.Snapshot, validatedAnalysis, diagnostics);

        Assert.False(valid, mutation);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotMalformed
            && diagnostic.Message.Contains(mutation is "dispatcher-entry" or "bounds-compare" or "bounds-branch" or "safe-default"
                ? "final external consumer instruction/reference chain" : "proven unchanged in-consumer GOT slot", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0x4000UL)]
    [InlineData(0x100000UL)]
    public void PublicationPreservesSeparateLayoutNeutralAndSourceAddressDomainsForRebasedConsumers(ulong sourceBaseDelta)
    {
        using var scenario = new PublicationScenario(sourceBaseDelta);
        Assert.True(scenario.Proof.SelectedFunction.Value >= sourceBaseDelta);
        Assert.True(scenario.Proof.GotSlotAddress.Value >= sourceBaseDelta);

        var result = scenario.Rehydrate(scenario.Artifact);

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.NativeImage);
    }

    [Fact]
    public void RehydrationRejectsAnExternalConsumerAfterProviderFactsAndCompanionAreBothRemoved()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var providerBytes = File.ReadAllBytes(FixturePath(ProviderFixture));
        using var directory = new TemporaryDirectory();
        var providerPath = directory.Path("operator-provider.so");
        File.WriteAllBytes(providerPath, providerBytes);
        var providerInput = CreateProviderInput(providerPath, providerBytes);
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request) with { ExternalJumpTableProviderInput = providerInput });
        Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));

        var decodedArtifact = ProtectedImageCodec.Decode(emission.ArtifactBytes!);
        Assert.True(decodedArtifact.IsSuccess, string.Join(Environment.NewLine, decodedArtifact.Diagnostics));
        var snapshotOperation = Assert.Single(
            decodedArtifact.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var snapshot = SemanticPlanSnapshotCodec.Decode(snapshotOperation.CanonicalBytes);
        Assert.True(snapshot.IsSuccess, string.Join(Environment.NewLine, snapshot.Diagnostics));
        var plan = snapshot.Snapshot!.Plan;
        var withoutProviderAndConsumer = SemanticPlanSnapshotCodec.Create(new SemanticRewritePlan(
            plan.AddressMap,
            plan.Instructions,
            plan.Fixups,
            plan.Extensions.Where(extension =>
                extension is not (SemanticExternalJumpTableExtension or SemanticExternalJumpTableConsumerExtension)),
            plan.Diagnostics));
        Assert.True(withoutProviderAndConsumer.IsSuccess,
            string.Join(Environment.NewLine, withoutProviderAndConsumer.Diagnostics));
        var operations = decodedArtifact.Image.Operations
            .Select(operation => operation is ProtectedImageSemanticPlanSnapshot
                ? new ProtectedImageSemanticPlanSnapshot(withoutProviderAndConsumer.Snapshot!)
                : operation)
            .ToArray();
        var mutatedArtifact = ProtectedImageCodec.Encode(decodedArtifact.Image with { Operations = operations });
        Assert.True(mutatedArtifact.IsSuccess, string.Join(Environment.NewLine, mutatedArtifact.Diagnostics));

        var result = GenericRehydrationEngine.Rehydrate(
            source,
            mutatedArtifact.ArtifactBytes!,
            RehydrationOptions(source, emission.Role!.RequestSha256));

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.IsError);
    }

    [Fact]
    public void ProviderFileSnapshotEnforcesTheEightMiBLimitAndRedactsItsPath()
    {
        using var directory = new TemporaryDirectory();
        var sentinel = directory.Path("DO_NOT_REPORT_OVERSIZED_PROVIDER.so");
        File.WriteAllBytes(
            sentinel,
            new byte[SemanticExternalJumpTableProviderReader.MaximumProviderElfBytes + 1]);

        var result = ExternalJumpTableProviderFileReader.Read(new ExternalJumpTableProviderInput(
            sentinel,
            ProviderSoname,
            ProviderBuildId,
            new string('a', 64)));
        var diagnosticText = string.Join(Environment.NewLine, result.Diagnostics);

        Assert.False(result.IsSuccess);
        Assert.Null(result.Bytes);
        Assert.Contains(result.Diagnostics, diagnostic =>
            diagnostic.Code == DiagnosticCode.SemanticPlanSnapshotLimitExceeded);
        Assert.DoesNotContain(sentinel, diagnosticText, StringComparison.Ordinal);
    }

    [Fact]
    public void ProducerDoesNotPublishExternalProviderFactsWithoutACompletePinnedInput()
    {
        var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
        var request = Request();
        var emission = new ProtectedImageProducer().Emit(
            source,
            request,
            ProducerOptions(source, request));

        Assert.False(emission.IsSuccess);
        Assert.Null(emission.ArtifactBytes);
        Assert.Contains(emission.Diagnostics, diagnostic =>
            diagnostic.Code is DiagnosticCode.IndirectTargetUnresolved or DiagnosticCode.IndirectTargetUnsupported);
    }

    private static int ChainOrdinal(string mutation) => mutation switch
    {
        "adrp" => 0,
        "got-load" => 1,
        "indexed-load" => 2,
        "add" => 3,
        "branch" => 4,
        _ => throw new ArgumentOutOfRangeException(nameof(mutation)),
    };

    private static uint ChangeChainWord(uint word, ulong address, Aarch64ExternalJumpTableConsumerProof proof, string mutation)
    {
        var encoder = new Aarch64InstructionEncoder();
        Aarch64InstructionEncodeResult changed;
        if (mutation == "adrp")
        {
            changed = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                word, address, address, Aarch64InstructionEncodingFamily.AdrPrelPgHi21,
                (proof.GotSlotAddress.Value & ~0xFFFUL) + 0x1000));
        }
        else if (mutation == "got-load")
        {
            changed = encoder.TryEncode(new Aarch64InstructionEncodeRequest(
                word, address, address, Aarch64InstructionEncodingFamily.LoadStoreUnsignedImmediate,
                (proof.GotSlotAddress.Value & 0xFFFUL) - sizeof(ulong), AccessWidth: 64));
        }
        else
        {
            // The shared adapter owns register-field encoding, including BR.
            var permutation = encoder.TryPermuteGeneralRegisters(word, address,
                new Dictionary<byte, byte> { [proof.TargetRegister.Index] = 10, [10] = proof.TargetRegister.Index,
                    [proof.GotPointerRegister.Index] = 11, [11] = proof.GotPointerRegister.Index });
            Assert.True(permutation.IsSuccess, permutation.Diagnostic);
            Assert.NotEqual(word, permutation.Encoding);
            return permutation.Encoding;
        }

        Assert.True(changed.IsSuccess, changed.Diagnostic);
        Assert.NotEqual(word, changed.Encoding);
        return changed.Encoding;
    }

    private sealed class PublicationScenario : IDisposable
    {
        private readonly TemporaryDirectory directory = new();
        private readonly string requestSha256;

        public PublicationScenario(ulong sourceBaseDelta = 0)
        {
            var provider = File.ReadAllBytes(FixturePath(ProviderFixture));
            var source = File.ReadAllBytes(FixturePath(ConsumerFixture));
            Source = sourceBaseDelta == 0 ? source : RebaseConsumerFixture(source, sourceBaseDelta);
            var providerPath = directory.Path("operator-provider.so");
            File.WriteAllBytes(providerPath, provider);
            ProviderInput = CreateProviderInput(providerPath, provider);
            var request = Request();
            var emission = new ProtectedImageProducer().Emit(Source, request,
                ProducerOptions(Source, request) with { ExternalJumpTableProviderInput = ProviderInput });
            Assert.True(emission.IsSuccess, string.Join(Environment.NewLine, emission.Diagnostics));
            Artifact = emission.ArtifactBytes!;
            requestSha256 = emission.Role!.RequestSha256;
            var image = ProtectedImageCodec.Decode(Artifact, Sha256(Source), requestSha256);
            Assert.True(image.IsSuccess, string.Join(Environment.NewLine, image.Diagnostics));
            Document = image.Image!;
            var operation = Assert.Single(Document.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
            var snapshot = SemanticPlanSnapshotCodec.Decode(operation.CanonicalBytes);
            Assert.True(snapshot.IsSuccess, string.Join(Environment.NewLine, snapshot.Diagnostics));
            Snapshot = snapshot.Snapshot!;
            Proof = Assert.Single(Snapshot.Extensions.OfType<SemanticExternalJumpTableConsumerExtension>()).ConsumerProof;
            var parsed = ElfParser.Parse(Source);
            Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
            SourceFile = parsed.File!;
        }

        public byte[] Source { get; }
        public byte[] Artifact { get; }
        public ElfFile SourceFile { get; }
        public ProtectedImageDocument Document { get; }
        public SemanticPlanSnapshot Snapshot { get; }
        public Aarch64ExternalJumpTableConsumerProof Proof { get; }
        public ExternalJumpTableProviderInput ProviderInput { get; }

        public byte[] Encode(SemanticRewritePlan plan)
        {
            var canonical = SemanticPlanSnapshotCodec.Create(plan);
            Assert.True(canonical.IsSuccess, string.Join(Environment.NewLine, canonical.Diagnostics));
            var decoded = SemanticPlanSnapshotCodec.Decode(canonical.Snapshot!.CanonicalBytes);
            Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
            var image = ProtectedImageCodec.Encode(Document with
            {
                Operations = Document.Operations.Select(operation => operation is ProtectedImageSemanticPlanSnapshot
                    ? new ProtectedImageSemanticPlanSnapshot(canonical.Snapshot) : operation).ToArray(),
            });
            Assert.True(image.IsSuccess, string.Join(Environment.NewLine, image.Diagnostics));
            Assert.True(ProtectedImageCodec.Decode(image.ArtifactBytes!, Sha256(Source), requestSha256).IsSuccess);
            return image.ArtifactBytes!;
        }

        public RehydrationResult Rehydrate(byte[] artifact) => GenericRehydrationEngine.Rehydrate(
            Source, artifact, RehydrationOptions(Source, requestSha256) with { ExternalJumpTableProviderInput = ProviderInput });

        public void Dispose() => directory.Dispose();
    }

    private static byte[] RebaseConsumerFixture(byte[] source, ulong delta)
    {
        // Rebase the existing linked fixture without changing any file offsets,
        // code displacements, provider bytes, or instruction encoding. This is
        // metadata-only test setup, not a second instruction writer.
        Assert.Equal(0UL, delta & 0xFFFUL);
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var file = parsed.File!;
        var bytes = source.ToArray();
        var programOffset = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(32, sizeof(ulong)));
        for (var index = 0; index < file.ProgramHeaders.Count; index++)
        {
            var header = file.ProgramHeaders[index];
            if (header.MemorySize == 0) continue;
            var offset = checked((int)(programOffset + ((ulong)index * 56)));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 16, sizeof(ulong)), header.VirtualAddress + delta);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 24, sizeof(ulong)), header.PhysicalAddress + delta);
        }

        var sectionOffset = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(40, sizeof(ulong)));
        for (var index = 0; index < file.SectionHeaders.Count; index++)
        {
            var offset = checked((int)(sectionOffset + ((ulong)index * 64)));
            if ((BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset + 8, sizeof(ulong))) & 2UL) == 0) continue;
            var address = BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(offset + 16, sizeof(ulong)));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset + 16, sizeof(ulong)), address + delta);
        }

        var dynamic = Assert.Single(file.ProgramHeaders, header => header.Type == ElfConstants.PtDynamic);
        var pointerTags = new[] { ElfConstants.DtGnuHash, ElfConstants.DtStrTab, ElfConstants.DtSymTab, ElfConstants.DtRela };
        for (var index = 0; index < file.DynamicEntries.Count; index++)
        {
            var entry = file.DynamicEntries[index];
            if (!pointerTags.Contains(entry.Tag)) continue;
            var offset = checked((int)(dynamic.Offset + ((ulong)index * 16) + 8));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset, sizeof(ulong)), entry.Value + delta);
        }

        var symbols = Assert.Single(file.DynamicEntries, entry => entry.Tag == ElfConstants.DtSymTab).Value;
        Assert.True(file.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(symbols), 1, out var symbolsOffset));
        for (var index = 0; index < file.DynamicSymbols.Count; index++)
        {
            var symbol = file.DynamicSymbols[index];
            if (symbol.SectionIndex == 0 || symbol.Value == 0) continue;
            var offset = checked((int)(symbolsOffset.Value + ((ulong)index * ElfConstants.SymbolEntrySize64) + 8));
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(offset, sizeof(ulong)), symbol.Value + delta);
        }

        foreach (var relocation in file.RelaRelocations)
        {
            Assert.Equal(ElfConstants.RArm64GlobDat, relocation.Type);
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(checked((int)relocation.SourceAddress), sizeof(ulong)), relocation.Offset + delta);
        }

        var rebased = ElfParser.Parse(bytes);
        Assert.True(rebased.IsSuccess, string.Join(Environment.NewLine, rebased.Diagnostics));
        Assert.Equal(file.FunctionSymbols.Select(function => function.Value + delta),
            rebased.File!.FunctionSymbols.Select(function => function.Value));
        return bytes;
    }

    private static FunctionProtectionOptions Request() => new(
        new[] { FunctionSelector.ByName("urp_entry") },
        new[] { ProtectionPass.ControlFlowFlattening });

    private static ProtectedImageProducerOptions ProducerOptions(
        byte[] source,
        FunctionProtectionOptions request) => new(
        "external-provider-publication-test",
        ProtectedImageProfile.OuterExecveat,
        "urprotect.tests.external-provider-producer",
        ProducerBuild,
        ProtectedImageAbiV1.DefaultRehydratorConsumerId,
        Sha256(source),
        ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes));

    private static RehydrationOptions RehydrationOptions(byte[] source, string requestSha256) => new(
        Sha256(source),
        requestSha256,
        "external-provider-publication-test",
        ProtectedImageProfile.OuterExecveat,
        "urprotect.tests.external-provider-producer",
        ProducerBuild,
        ProtectedImageAbiV1.DefaultRehydratorConsumerId,
        ConsumerBuild);

    private static byte[] MutateSource(
        byte[] source,
        Aarch64ExternalJumpTableConsumerProof proof,
        string mutation)
    {
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var bytes = source.ToArray();
        switch (mutation)
        {
            case "relocation-owner":
                var relocation = Assert.Single(parsed.File!.RelaRelocations,
                    candidate => candidate.Offset == proof.GotSlotAddress.Value);
                Assert.NotEqual(ElfConstants.RArm64JumpSlot, relocation.Type);
                var mutatedInfo = (relocation.Info & 0xFFFFFFFF00000000UL) | ElfConstants.RArm64JumpSlot;
                BinaryPrimitives.WriteUInt64LittleEndian(
                    bytes.AsSpan(checked((int)relocation.SourceAddress + sizeof(ulong)), sizeof(ulong)),
                    mutatedInfo);
                break;
            case "got-permissions":
                var gotAddress = proof.GotSlotAddress.Value;
                var writableSegment = Assert.Single(parsed.File!.ProgramHeaders, header =>
                    header.Type == ElfConstants.PtLoad
                    && (header.Flags & ElfConstants.PfW) != 0
                    && header.MemorySize >= sizeof(ulong)
                    && gotAddress >= header.VirtualAddress
                    && gotAddress - header.VirtualAddress <= header.MemorySize - sizeof(ulong));
                var segmentIndex = parsed.File.ProgramHeaders.ToList().FindIndex(header => header == writableSegment);
                Assert.True(segmentIndex >= 0);
                var programHeaderOffset = checked((int)BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(32, sizeof(ulong)))
                    + (segmentIndex * 56));
                var flagsOffset = checked(programHeaderOffset + sizeof(uint));
                var flags = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(flagsOffset, sizeof(uint)));
                BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(flagsOffset, sizeof(uint)), flags & ~ElfConstants.PfW);
                break;
            case "consumer-chain":
                Assert.True(parsed.File!.LoadMap.TryVirtualAddressToFileOffset(
                    new VirtualAddress(proof.GotLoadProducerAddress),
                    sizeof(uint),
                    out var instructionOffset));
                BinaryPrimitives.WriteUInt32LittleEndian(
                    bytes.AsSpan(checked((int)instructionOffset.Value), sizeof(uint)),
                    0xD503201Fu);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Unknown source mutation.");
        }

        return bytes;
    }

    private static ExternalJumpTableProviderInput CreateProviderInput(string path, byte[] providerBytes) => new(
        path,
        ProviderSoname,
        ProviderBuildId,
        Sha256(providerBytes));

    private static string FixturePath(string relativePath) => Path.Combine(
        AppContext.BaseDirectory,
        relativePath.Replace('/', Path.DirectorySeparatorChar));

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static byte[] EncodeSnapshotString(string value)
    {
        var encoded = Encoding.UTF8.GetBytes(value);
        var result = new byte[sizeof(uint) + encoded.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(result, checked((uint)encoded.Length));
        encoded.CopyTo(result.AsSpan(sizeof(uint)));
        return result;
    }

    private static void RefreshSnapshotDigest(byte[] bytes)
    {
        const int digestSize = 32;
        var contentLength = bytes.Length - digestSize;
        SHA256.HashData(bytes.AsSpan(0, contentLength)).CopyTo(bytes.AsSpan(contentLength));
    }

    private sealed class RejectExternalGotPageEncoder : IAarch64InstructionEncoder
    {
        private readonly IAarch64InstructionEncoder inner;
        private readonly ulong gotPageAddress;

        public RejectExternalGotPageEncoder(IAarch64InstructionEncoder inner, ulong gotPageAddress)
        {
            this.inner = inner;
            this.gotPageAddress = gotPageAddress;
        }

        public bool Rejected { get; private set; }

        public Aarch64InstructionEncodeResult TryEncode(Aarch64InstructionEncodeRequest request)
        {
            if (request.Family == Aarch64InstructionEncodingFamily.AdrPrelPgHi21
                && request.TargetOrImmediate == gotPageAddress)
            {
                Rejected = true;
                return Aarch64InstructionEncodeResult.Failure(
                    Aarch64InstructionEncodeDiagnosticCode.TargetOutOfRange,
                    "The test encoder rejected the external consumer GOT page.");
            }

            return inner.TryEncode(request);
        }

        public Aarch64InstructionEncodeResult TryCreate(Aarch64InstructionBuildRequest request) => inner.TryCreate(request);

        public Aarch64EncodeResult TryPermuteGeneralRegisters(
            uint encoding,
            ulong address,
            IReadOnlyDictionary<byte, byte> mapping) => inner.TryPermuteGeneralRegisters(encoding, address, mapping);
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-external-provider-");

        public string Path(string fileName) => System.IO.Path.Combine(directory.FullName, fileName);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
