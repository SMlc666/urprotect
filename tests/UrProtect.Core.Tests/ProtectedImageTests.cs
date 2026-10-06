using System.Buffers.Binary;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Protect;

namespace UrProtect.Core.Tests;

public sealed class ProtectedImageTests
{
    private const string VersionedFixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";
    private static readonly string[] StageSelectors = { "table=symtab, index=23" };
    private static readonly string[] StagePasses = { "control-flow-flattening" };

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void CodecRoundTripsAHashBoundStructuredArtifactDeterministically()
    {
        var image = CreateImage();

        var first = ProtectedImageCodec.Encode(image);
        var second = ProtectedImageCodec.Encode(image);

        Assert.True(first.IsSuccess, string.Join(Environment.NewLine, first.Diagnostics));
        Assert.True(second.IsSuccess, string.Join(Environment.NewLine, second.Diagnostics));
        Assert.Equal(first.ArtifactBytes, second.ArtifactBytes);
        Assert.NotNull(first.ArtifactBytes);
        var artifact = first.ArtifactBytes!;
        Assert.Equal((uint)artifact.Length, BinaryPrimitives.ReadUInt32LittleEndian(artifact.AsSpan(12, sizeof(uint))));
        Assert.Equal((ushort)ElfConstants.MachineAarch64, BinaryPrimitives.ReadUInt16LittleEndian(artifact.AsSpan(6, sizeof(ushort))));
        var canonicalDigest = SHA256.HashData(artifact.AsSpan(0, artifact.Length - 32));
        Assert.Equal(canonicalDigest, artifact.AsSpan(artifact.Length - 32).ToArray());
        Assert.Equal(
            ProtectedImageAbiV1.ComputeArtifactSha256(artifact),
            Convert.ToHexString(SHA256.HashData(artifact)).ToLowerInvariant());

        var decoded = ProtectedImageCodec.Decode(first.ArtifactBytes!, image.SourceSha256, image.RequestSha256);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        Assert.Equal(image.UnitId, decoded.Image!.UnitId);
        Assert.Equal(image.Operations.Count, decoded.Image.Operations.Count);
        Assert.Equal(image.RequestSha256, decoded.Image.RequestSha256);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void CodecRejectsTruncationDigestMutationUnknownOperationAndOverlap()
    {
        var encoded = ProtectedImageCodec.Encode(CreateImage());
        Assert.True(encoded.IsSuccess);
        var artifact = encoded.ArtifactBytes!;

        var truncated = ProtectedImageCodec.Decode(artifact.AsMemory(0, artifact.Length - 1));
        Assert.False(truncated.IsSuccess);

        var mutated = artifact.ToArray();
        mutated[0] = (byte)'X';
        var malformedMagic = ProtectedImageCodec.Decode(mutated);
        Assert.Contains(malformedMagic.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);

        var integrity = artifact.ToArray();
        integrity[^1] ^= 0x01;
        var integrityFailure = ProtectedImageCodec.Decode(integrity);
        Assert.Contains(integrityFailure.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageIntegrityMismatch);

        var overlap = CreateImage() with
        {
            Operations = new ProtectedImageOperation[]
            {
                new ProtectedImageEmitRegion(1, new VirtualAddress(0x1000), 4, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(1, 1, new VirtualAddress(0x1000), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
                new ProtectedImageEmitRegion(2, new VirtualAddress(0x1000), 4, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(2, 2, new VirtualAddress(0x1000), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
            },
        };
        var overlapResult = ProtectedImageCodec.Encode(overlap);
        Assert.False(overlapResult.IsSuccess);
        Assert.Contains(overlapResult.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageOverlap);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void CodecRejectsOverflowDuplicateAndUnknownAbiRecords()
    {
        var duplicate = CreateImage() with
        {
            Operations = new ProtectedImageOperation[]
            {
                new ProtectedImageEmitRegion(1, new VirtualAddress(0x1000), 4, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(1, 1, new VirtualAddress(0x1000), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
                new ProtectedImageEmitRegion(1, new VirtualAddress(0x2000), 4, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(1, 1, new VirtualAddress(0x1000), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
            },
        };
        var duplicateResult = ProtectedImageCodec.Encode(duplicate);
        Assert.False(duplicateResult.IsSuccess);
        Assert.Contains(duplicateResult.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageDuplicateRecord);

        var overflow = CreateImage() with
        {
            Operations = new ProtectedImageOperation[]
            {
                new ProtectedImageEmitRegion(1, new VirtualAddress(ulong.MaxValue - 3), 8, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(1, 1, new VirtualAddress(ulong.MaxValue - 3), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
            },
        };
        var overflowResult = ProtectedImageCodec.Encode(overflow);
        Assert.False(overflowResult.IsSuccess);
        Assert.Contains(overflowResult.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);

        var invalidFixup = CreateImage() with
        {
            Operations = new ProtectedImageOperation[]
            {
                new ProtectedImageEmitRegion(1, new VirtualAddress(0x1000), 4, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(1, 1, new VirtualAddress(0x2000), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
            },
        };
        var invalidFixupResult = ProtectedImageCodec.Encode(invalidFixup);
        Assert.False(invalidFixupResult.IsSuccess);
        Assert.Contains(invalidFixupResult.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);

        var encoded = ProtectedImageCodec.Encode(CreateImage());
        Assert.True(encoded.IsSuccess);
        var unknownVersion = encoded.ArtifactBytes!.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(unknownVersion.AsSpan(4), 99);
        RecomputeCanonicalDigest(unknownVersion);
        var unknownVersionResult = ProtectedImageCodec.Decode(unknownVersion);
        Assert.False(unknownVersionResult.IsSuccess);
        Assert.Contains(unknownVersionResult.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageUnsupported);

        var unknownOperation = encoded.ArtifactBytes!.ToArray();
        var operationMarker = new byte[] { 1, 0, 0, 0, 36, 0, 0, 0 };
        var operationOffset = unknownOperation.AsSpan().IndexOf(operationMarker);
        Assert.True(operationOffset >= 0);
        unknownOperation[operationOffset] = 99;
        RecomputeCanonicalDigest(unknownOperation);
        var unknownOperationResult = ProtectedImageCodec.Decode(unknownOperation);
        Assert.False(unknownOperationResult.IsSuccess);
        Assert.Contains(unknownOperationResult.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageUnsupported);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void ProducerEmitsWithoutAProgramHeaderSlotAndBindsSourceAndRequest()
    {
        var source = File.ReadAllBytes(VersionedFixturePath);
        var parsed = ElfParser.Parse(source);
        Assert.NotNull(parsed.File);
        Assert.DoesNotContain(parsed.File!.ProgramHeaders, header => header.Type == ElfConstants.PtNull);
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceSha256 = Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant();
        var options = new ProtectedImageProducerOptions(
            "compat.protection-symbolized-fixture.glibc.outer-execveat",
            ProtectedImageProfile.OuterExecveat,
            "urprotect.tests.producer",
            new string('a', 64),
            ProtectedImageAbiV1.DefaultRehydratorConsumerId,
            sourceSha256,
            ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes));

        var first = new ProtectedImageProducer().Emit(source, request, options);
        var second = new ProtectedImageProducer().Emit(source, request, options);

        Assert.True(first.IsSuccess, string.Join(Environment.NewLine, first.Diagnostics));
        Assert.True(second.IsSuccess, string.Join(Environment.NewLine, second.Diagnostics));
        Assert.Equal(first.ArtifactBytes, second.ArtifactBytes);
        Assert.NotNull(first.Role);
        Assert.Equal(sourceSha256, first.Role!.SourceSha256);
        Assert.Equal(options.RehydratorConsumerId, first.Role.RehydratorConsumerId);
        Assert.False(first.Role.RawArtifactRetained);
        Assert.Equal(string.Empty, first.Role.RawArtifactPath);
        Assert.NotEqual(source, first.ArtifactBytes);
        Assert.DoesNotContain(first.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectionLayoutUnavailable);

        var decoded = ProtectedImageCodec.Decode(first.ArtifactBytes!, sourceSha256, options.ExpectedRequestSha256);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void CodecRejectsBoundedArbitraryBytesWithoutThrowing()
    {
        var random = new Random(0x51A7);
        for (var iteration = 0; iteration < 256; iteration++)
        {
            var bytes = new byte[random.Next(0, 512)];
            random.NextBytes(bytes);

            var exception = Record.Exception(() => ProtectedImageCodec.Decode(bytes));

            Assert.Null(exception);
        }
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void CodecRejectsSourceAndRequestBindingMismatch()
    {
        var image = CreateImage();
        var encoded = ProtectedImageCodec.Encode(image);
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));

        var sourceMismatch = ProtectedImageCodec.Decode(
            encoded.ArtifactBytes!,
            new string('f', 64),
            image.RequestSha256);
        Assert.False(sourceMismatch.IsSuccess);
        Assert.Contains(sourceMismatch.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageSourceMismatch);

        var requestMismatch = ProtectedImageCodec.Decode(
            encoded.ArtifactBytes!,
            image.SourceSha256,
            new string('e', 64));
        Assert.False(requestMismatch.IsSuccess);
        Assert.Contains(requestMismatch.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageRequestMismatch);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void CodecRejectsACompleteElfAsAProtectedImageAlias()
    {
        var source = File.ReadAllBytes(VersionedFixturePath);

        var result = ProtectedImageCodec.Decode(source);

        Assert.False(result.IsSuccess);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void ProducerRejectsSourceMismatchBeforePublication()
    {
        var source = File.ReadAllBytes(VersionedFixturePath);
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var options = new ProtectedImageProducerOptions(
            "unit",
            ProtectedImageProfile.OuterExecveat,
            "producer",
            new string('b', 64),
            ProtectedImageAbiV1.DefaultRehydratorConsumerId,
            new string('c', 64));

        var result = new ProtectedImageProducer().Emit(source, request, options);

        Assert.False(result.IsSuccess);
        Assert.Null(result.ArtifactBytes);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageSourceMismatch);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void StageRecordRequiresBoundedDigestAndPublicationBindings()
    {
        var stage = new ProtectedImageStageRecord(
            1,
            ProtectedImageStageRecord.ProducerStage,
            ProtectedImageStageRecord.PassedStatus,
            "unit.fixture",
            ProtectedImageProfile.OuterExecveat.ToCliValue(),
            new string('1', 64),
            new string('2', 64),
            "producer.fixture",
            new string('3', 64),
            ProtectedImageAbiV1.DefaultRehydratorConsumerId,
            new string('4', 64),
            64,
            new string('5', 64),
            new string('6', 64),
            "image.bin",
            "protected-image.json",
            "SHA256SUMS",
            "passed",
            1,
            StageSelectors,
            StagePasses,
            Array.Empty<ProtectedImageStageDiagnostic>(),
            ProtectedImageAbiV1.ArtifactRole,
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            true);
        var diagnostics = new DiagnosticBag();

        Assert.True(stage.Validate(diagnostics), string.Join(Environment.NewLine, diagnostics));
        var malformed = stage with { CommandDigest = "not-a-digest" };
        var malformedDiagnostics = new DiagnosticBag();
        Assert.False(malformed.Validate(malformedDiagnostics));
        Assert.Contains(malformedDiagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void PublisherWritesHashBoundArtifactRoleAndManifestAtomically()
    {
        var image = CreateImage();
        var encoded = ProtectedImageCodec.Encode(image);
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));
        var artifact = encoded.ArtifactBytes!;
        var role = CreateRole(image, artifact);
        var emission = new ProtectedImageEmissionResult(
            role,
            artifact,
            Array.Empty<FunctionProtectionFunctionResult>(),
            Array.Empty<Diagnostic>());
        using var directory = new TemporaryDirectory();
        var artifactPath = directory.Path("image.bin");
        var rolePath = directory.Path("protected-image.json");
        var manifestDirectory = Directory.CreateDirectory(directory.Path("manifest"));
        var manifestPath = System.IO.Path.Combine(manifestDirectory.FullName, "SHA256SUMS");

        var publication = ProtectedImagePublisher.Publish(emission, artifactPath, rolePath, manifestPath);

        Assert.True(publication.Published, string.Join(Environment.NewLine, publication.Diagnostics));
        Assert.Equal(artifact, File.ReadAllBytes(artifactPath));
        Assert.Contains("protected-image", File.ReadAllText(rolePath), StringComparison.Ordinal);
        var manifest = File.ReadAllText(manifestPath);
        Assert.Contains(ProtectedImageAbiV1.ComputeArtifactSha256(artifact), manifest, StringComparison.Ordinal);
        Assert.Contains("../image.bin", manifest, StringComparison.Ordinal);
        Assert.Contains("../protected-image.json", manifest, StringComparison.Ordinal);
        Assert.Empty(Directory.GetFiles(directory.RootPath, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void PublisherRejectsRoleIdentityMismatchBeforePublication()
    {
        var image = CreateImage();
        var encoded = ProtectedImageCodec.Encode(image);
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));
        var role = CreateRole(image, encoded.ArtifactBytes!) with { ProducerId = "other.producer" };
        var emission = new ProtectedImageEmissionResult(
            role,
            encoded.ArtifactBytes,
            Array.Empty<FunctionProtectionFunctionResult>(),
            Array.Empty<Diagnostic>());
        using var directory = new TemporaryDirectory();
        var artifactPath = directory.Path("image.bin");
        var rolePath = directory.Path("protected-image.json");

        var publication = ProtectedImagePublisher.Publish(emission, artifactPath, rolePath);

        Assert.False(publication.Published);
        Assert.Contains(publication.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageRoleMismatch);
        Assert.False(File.Exists(artifactPath));
        Assert.False(File.Exists(rolePath));
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void PublisherRemovesEarlierMoveWhenLaterDestinationAlreadyExists()
    {
        var image = CreateImage();
        var encoded = ProtectedImageCodec.Encode(image);
        Assert.True(encoded.IsSuccess, string.Join(Environment.NewLine, encoded.Diagnostics));
        var role = CreateRole(image, encoded.ArtifactBytes!);
        var emission = new ProtectedImageEmissionResult(
            role,
            encoded.ArtifactBytes,
            Array.Empty<FunctionProtectionFunctionResult>(),
            Array.Empty<Diagnostic>());
        using var directory = new TemporaryDirectory();
        var artifactPath = directory.Path("image.bin");
        var rolePath = directory.Path("protected-image.json");
        File.WriteAllText(rolePath, "existing");

        var publication = ProtectedImagePublisher.Publish(emission, artifactPath, rolePath);

        Assert.False(publication.Published);
        Assert.False(File.Exists(artifactPath));
        Assert.Equal("existing", File.ReadAllText(rolePath));
        Assert.Empty(Directory.GetFiles(directory.RootPath, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void PublisherRejectsACompleteElfBeforePublication()
    {
        var source = File.ReadAllBytes(VersionedFixturePath);
        var role = new ProtectedImageRoleRecord(
            1,
            ProtectedImageAbiV1.ArtifactRole,
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            "unit.fixture",
            ProtectedImageProfile.OuterExecveat.ToCliValue(),
            new string('1', 64),
            ProtectedImageAbiV1.ComputeArtifactSha256(source),
            source.LongLength,
            "producer.fixture",
            new string('2', 64),
            ProtectedImageAbiV1.DefaultRehydratorConsumerId,
            new string('3', 64),
            Array.Empty<string>(),
            Array.Empty<string>(),
            string.Empty,
            false);
        var emission = new ProtectedImageEmissionResult(
            role,
            source,
            Array.Empty<FunctionProtectionFunctionResult>(),
            Array.Empty<Diagnostic>());
        using var directory = new TemporaryDirectory();

        var publication = ProtectedImagePublisher.Publish(
            emission,
            directory.Path("image.bin"),
            directory.Path("protected-image.json"));

        Assert.False(publication.Published);
        Assert.Contains(publication.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);
        Assert.Empty(Directory.GetFiles(directory.RootPath, "*.tmp", SearchOption.AllDirectories));
    }

    [Fact]
    [Trait("Category", "ProtectedImage")]
    public void PublisherDoesNotPublishFailedEmissionOrPartialTemporaryFiles()
    {
        var emission = new ProtectedImageEmissionResult(
            null,
            null,
            Array.Empty<FunctionProtectionFunctionResult>(),
            new[]
            {
                new Diagnostic(
                    DiagnosticSeverity.Error,
                    DiagnosticCode.ProtectedImageMalformed,
                    "synthetic failure"),
            });
        using var directory = new TemporaryDirectory();
        var artifactPath = directory.Path("image.bin");
        var rolePath = directory.Path("protected-image.json");

        var publication = ProtectedImagePublisher.Publish(emission, artifactPath, rolePath);

        Assert.False(publication.Published);
        Assert.False(File.Exists(artifactPath));
        Assert.False(File.Exists(rolePath));
        Assert.Empty(Directory.GetFiles(directory.RootPath, "*.tmp", SearchOption.AllDirectories));
    }

    private static void RecomputeCanonicalDigest(byte[] artifact)
    {
        SHA256.HashData(artifact.AsSpan(0, artifact.Length - 32))
            .CopyTo(artifact.AsSpan(artifact.Length - 32));
    }

    private static ProtectedImageRoleRecord CreateRole(
        ProtectedImageDocument image,
        byte[] artifact) =>
        new(
            1,
            ProtectedImageAbiV1.ArtifactRole,
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            image.UnitId,
            image.Profile.ToCliValue(),
            image.SourceSha256,
            ProtectedImageAbiV1.ComputeArtifactSha256(artifact),
            artifact.LongLength,
            image.ProducerId,
            image.ProducerBuildSha256,
            image.RehydratorConsumerId,
            image.RequestSha256,
            image.Selectors,
            image.Passes.Select(ProtectionPassOrdering.Describe).ToArray(),
            string.Empty,
            false);

    private static ProtectedImageDocument CreateImage()
    {
        var selectors = new[] { "table=symtab, index=23" };
        var passes = new[] { ProtectionPass.ControlFlowFlattening };
        return new ProtectedImageDocument(
            "unit.fixture",
            ProtectedImageProfile.OuterExecveat,
            new string('1', 64),
            "producer.fixture",
            new string('2', 64),
            ProtectedImageAbiV1.DefaultRehydratorConsumerId,
            ProtectedImageCodec.ComputeRequestSha256(selectors, passes),
            selectors,
            passes,
            new ProtectedImageOperation[]
            {
                new ProtectedImageEmitRegion(1, new VirtualAddress(0x1000), 4, new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(1, 1, new VirtualAddress(0x1000), 0, 0, ProtectedImageFixupKind.Aarch64Branch26),
            });
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-protected-image-");

        public string RootPath => directory.FullName;

        public string Path(string fileName) => System.IO.Path.Combine(directory.FullName, fileName);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
