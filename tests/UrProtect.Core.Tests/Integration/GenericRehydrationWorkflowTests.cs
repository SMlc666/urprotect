using System.Security.Cryptography;
using System.Text.Json;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.ElfLayout;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.Infrastructure.Rehydration;
using UrProtect.Core.Tests.Structural;

namespace UrProtect.Core.Tests.Integration;

public sealed class GenericRehydrationTests
{
    private const string FixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";
    private const string UnitId = "compat.protection-symbolized-fixture.glibc.outer-execveat";
    private const string ProducerId = "gcc-c-protection-fixture";
    private const string ConsumerId = "urprotect.rehydrator.v1";
    private static readonly string ProducerBuild = new('a', 64);
    private static readonly string ConsumerBuild = new('b', 64);

    [Fact]
    [Trait("Category", "Rehydration")]
    public void OperationStreamMaterializesDeterministicDistinctAndReparsedNativeImage()
    {
        var source = CreateSourceWithProgramHeaderSlot();
        var emitted = Emit(source);
        var options = Options(source, emitted.Role!.RequestSha256);

        var first = GenericRehydrationEngine.Rehydrate(source, emitted.ArtifactBytes!, options);
        var second = GenericRehydrationEngine.Rehydrate(source, emitted.ArtifactBytes!, options);

        Assert.True(first.IsSuccess, string.Join(Environment.NewLine, first.Diagnostics));
        Assert.True(second.IsSuccess, string.Join(Environment.NewLine, second.Diagnostics));
        Assert.NotNull(first.NativeImage);
        Assert.Equal(first.NativeImage!.Bytes, second.NativeImage!.Bytes);
        Assert.NotEqual(Sha256(source), first.NativeImage.Descriptor.NativeImageSha256);
        Assert.NotEqual(Sha256(emitted.ArtifactBytes!), first.NativeImage.Descriptor.NativeImageSha256);
        Assert.Equal(first.Record.NativeImageSha256, first.NativeImage.Descriptor.NativeImageSha256);
        Assert.Equal(UnitId, first.Record.UnitId);
        Assert.Equal("outer-execveat", first.Record.Profile);
        Assert.Equal("outer-execveat-validated", first.Record.ProfileValidationStatus);
        Assert.Equal("kernel.execveat-at-empty-path", first.Record.LoaderIdentity);
        Assert.Equal("kernel.execveat-at-empty-path", first.NativeImage.Descriptor.LoaderIdentity);
        Assert.Equal(ConsumerId, first.Record.ConsumerId);
        Assert.Equal("passed", first.Record.Status);
        Assert.True(ElfParser.Parse(first.NativeImage.Bytes).IsSuccess);
        Assert.Contains(first.NativeImage.ParsedImage.ProgramHeaders, header =>
            header.Type == ElfConstants.PtLoad
            && header.Flags == (ElfConstants.PfR | ElfConstants.PfX)
            && header.Offset >= (ulong)source.Length);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationAndLayoutIgnoreUnknownBytesInAnUnselectedExecutableFunction()
    {
        var source = CreateSourceWithProgramHeaderSlot();
        var parsed = ElfParser.Parse(source);
        Assert.NotNull(parsed.File);
        var unrelated = Assert.Single(parsed.File!.FunctionSymbols, function =>
            function.Table == ElfSymbolTableKind.Static && function.TableIndex == 21);
        Assert.True(unrelated.Size >= sizeof(uint));
        Assert.True(parsed.File.LoadMap.TryVirtualAddressToFileOffset(
            unrelated.Value,
            sizeof(uint),
            out var unrelatedOffset));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            source.AsSpan(checked((int)unrelatedOffset)),
            0xFFFFFFFF);

        var emitted = Emit(source);
        var result = GenericRehydrationEngine.Rehydrate(
            source,
            emitted.ArtifactBytes!,
            Options(source, emitted.Role!.RequestSha256));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.NativeImage);
        Assert.NotNull(result.NativeImage!.LayoutEvidence);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RehydrationAcceptsAValidNonTlsSemanticSnapshotHandoff()
    {
        var source = ElfFixture.ExactIndirectBranchFunctionPie();
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByAddress(0x1200) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var emitted = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                UnitId,
                ProtectedImageProfile.OuterExecveat,
                ProducerId,
                ProducerBuild,
                ConsumerId,
                sourceHash,
                requestHash));
        Assert.True(emitted.IsSuccess, string.Join(Environment.NewLine, emitted.Diagnostics));
        var decoded = ProtectedImageCodec.Decode(emitted.ArtifactBytes!).Image!;
        var snapshotOperation = Assert.Single(
            decoded.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        var result = GenericRehydrationEngine.Rehydrate(
            source,
            emitted.ArtifactBytes!,
            Options(source, emitted.Role!.RequestSha256));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.NativeImage);
        Assert.Equal("passed", result.Record.Status);
        Assert.DoesNotContain(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.ProtectedImageMalformed);
        Assert.NotEmpty(snapshotOperation.CanonicalBytes);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RelativeJumpTableSnapshotFlowsThroughSharedLayoutAndReparse()
    {
        var source = ElfFixture.RelativeJumpTableFunctionPie();
        var parsed = ElfParser.Parse(source);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        var selected = Assert.Single(
            parsed.File!.FunctionSymbols,
            function => function.Table == ElfSymbolTableKind.Static
                && function.Value == 0x1200);
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, selected.TableIndex) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var emitted = new ProtectedImageProducer().Emit(
            source,
            request,
            new ProtectedImageProducerOptions(
                UnitId,
                ProtectedImageProfile.OuterExecveat,
                ProducerId,
                ProducerBuild,
                ConsumerId,
                sourceHash,
                requestHash));
        Assert.True(emitted.IsSuccess, string.Join(Environment.NewLine, emitted.Diagnostics));

        var decoded = ProtectedImageCodec.Decode(emitted.ArtifactBytes!, sourceHash, requestHash);
        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        var snapshot = Assert.Single(
            decoded.Image!.Operations.OfType<ProtectedImageSemanticPlanSnapshot>());
        Assert.NotEmpty(snapshot.CanonicalBytes);

        var result = GenericRehydrationEngine.Rehydrate(
            source,
            emitted.ArtifactBytes!,
            Options(source, emitted.Role!.RequestSha256));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.NativeImage);
        Assert.NotNull(result.NativeImage!.LayoutEvidence);
        Assert.Contains(
            result.NativeImage.LayoutEvidence!.JumpTableEdits,
            edit => edit.Kind == ElfLayoutEditKind.JumpTableEntry);
        Assert.Equal(RehydrationRecord.PassedStatus, result.Record.Status);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void RejectsTransformedTlsRelocationWhenSemanticSnapshotIsMissing()
    {
        var source = ElfFixture.TlsStaticRelocationPie();
        var selectors = new[] { "tls-fixture" };
        var passes = new[] { ProtectionPass.ControlFlowFlattening };
        var requestSha256 = ProtectedImageCodec.ComputeRequestSha256(selectors, passes);
        var sourceSha256 = Sha256(source);
        var image = new ProtectedImageDocument(
            "tls-fixture",
            ProtectedImageProfile.OuterExecveat,
            sourceSha256,
            "tls-test-producer",
            ProducerBuild,
            ConsumerId,
            requestSha256,
            selectors,
            passes,
            new ProtectedImageOperation[]
            {
                new ProtectedImageEmitRegion(1, new VirtualAddress(0x1200), sizeof(uint), new byte[] { 0, 0, 0, 0 }),
                new ProtectedImageEntryBranchFixup(
                    1,
                    1,
                    new VirtualAddress(0x1200),
                    0,
                    0,
                    ProtectedImageFixupKind.Aarch64Branch26),
            });
        var artifact = ProtectedImageCodec.Encode(image);
        Assert.True(artifact.IsSuccess, string.Join(Environment.NewLine, artifact.Diagnostics));
        var options = new RehydrationOptions(
            sourceSha256,
            requestSha256,
            image.UnitId,
            image.Profile,
            image.ProducerId,
            ProducerBuild,
            ConsumerId,
            ConsumerBuild);

        var result = GenericRehydrationEngine.Rehydrate(source, artifact.ArtifactBytes!, options);

        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.TlsBindingUnresolved);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void OccupiedProgramHeaderTableUsesRelocatedTableWithoutNativeImageFallback()
    {
        var source = File.ReadAllBytes(FixturePath);
        var emitted = Emit(source);
        var result = GenericRehydrationEngine.Rehydrate(source, emitted.ArtifactBytes!, Options(source, emitted.Role!.RequestSha256));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.NativeImage);
        Assert.NotNull(result.NativeImage!.LayoutEvidence);
        Assert.Equal(ElfLayoutStrategy.RelocatedProgramHeaderTable, result.NativeImage.LayoutEvidence!.Strategy);
        Assert.Equal("relocated-program-header-table", result.Record.LayoutStrategy);
        Assert.Equal(ElfConstants.PtLoad, result.NativeImage.ParsedImage.ProgramHeaders[^1].Type);
        Assert.True(result.NativeImage.ParsedImage.Header.ProgramHeaderOffset >= (ulong)source.Length);
        Assert.Equal(
            (ushort)(ElfParser.Parse(source).File!.Header.ProgramHeaderCount + 1),
            result.NativeImage.ParsedImage.Header.ProgramHeaderCount);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void SourceRequestProfileProducerAndConsumerBindingsFailClosed()
    {
        var source = CreateSourceWithProgramHeaderSlot();
        var emitted = Emit(source);
        var image = ProtectedImageCodec.Decode(emitted.ArtifactBytes!, Sha256(source)).Image!;
        var artifact = emitted.ArtifactBytes!;
        var baseline = Options(source, image.RequestSha256);

        AssertFailure(baseline with { ExpectedSourceSha256 = new string('c', 64) }, source, artifact, DiagnosticCode.ProtectedImageSourceMismatch);
        AssertFailure(baseline with { ExpectedRequestSha256 = new string('d', 64) }, source, artifact, DiagnosticCode.ProtectedImageRequestMismatch);
        AssertFailure(baseline with { ExpectedProfile = ProtectedImageProfile.HostContextEntry }, source, artifact, DiagnosticCode.ProtectedImageProfileMismatch);
        AssertFailure(baseline with { ExpectedProducerId = "other.producer" }, source, artifact, DiagnosticCode.ProtectedImageRoleMismatch);
        AssertFailure(baseline with { ExpectedProducerBuildSha256 = new string('e', 64) }, source, artifact, DiagnosticCode.ProtectedImageRoleMismatch);
        AssertFailure(baseline with { ExpectedConsumerId = "other.consumer.v1" }, source, artifact, DiagnosticCode.ProtectedImageConsumerMismatch);

        var tampered = artifact.ToArray();
        tampered[^1] ^= 0x80;
        AssertFailure(baseline, source, tampered, DiagnosticCode.ProtectedImageIntegrityMismatch);
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void PublisherAtomicallyRetainsSuccessRecordsAndOmitsNativeImageOnFailure()
    {
        var source = CreateSourceWithProgramHeaderSlot();
        var emitted = Emit(source);
        var result = GenericRehydrationEngine.Rehydrate(source, emitted.ArtifactBytes!, Options(source, emitted.Role!.RequestSha256));
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        using var directory = new TemporaryDirectory();
        var nativePath = directory.Path("native-image.bin");
        var rolePath = directory.Path("native-image.json");
        var recordPath = directory.Path("rehydration.json");

        var publication = RehydrationPublisher.Publish(result, nativePath, rolePath, recordPath);

        Assert.True(publication.Published, string.Join(Environment.NewLine, publication.Diagnostics));
        Assert.Equal(result.NativeImage!.Bytes, File.ReadAllBytes(nativePath));
        using var roleDocument = JsonDocument.Parse(File.ReadAllText(rolePath));
        Assert.Equal("native-image", roleDocument.RootElement.GetProperty("artifactRole").GetString());
        Assert.Equal(result.Record.NativeImageSha256, roleDocument.RootElement.GetProperty("nativeImageSha256").GetString());
        Assert.Equal(Sha256(File.ReadAllBytes(recordPath)), roleDocument.RootElement.GetProperty("rehydrationRecordSha256").GetString());
        Assert.Empty(Directory.GetFiles(directory.Root, "*.tmp", SearchOption.AllDirectories));

        var failed = GenericRehydrationEngine.Rehydrate(
            File.ReadAllBytes(FixturePath),
            emitted.ArtifactBytes!,
            Options(File.ReadAllBytes(FixturePath), emitted.Role!.RequestSha256));
        var failedDirectory = Directory.CreateTempSubdirectory("urprotect-rehydration-failure-");
        try
        {
            var failedPublication = RehydrationPublisher.Publish(
                failed,
                System.IO.Path.Combine(failedDirectory.FullName, "native-image.bin"),
                System.IO.Path.Combine(failedDirectory.FullName, "native-image.json"),
                System.IO.Path.Combine(failedDirectory.FullName, "rehydration.json"));
            Assert.True(failedPublication.Published, string.Join(Environment.NewLine, failedPublication.Diagnostics));
            Assert.False(File.Exists(System.IO.Path.Combine(failedDirectory.FullName, "native-image.bin")));
            Assert.False(File.Exists(System.IO.Path.Combine(failedDirectory.FullName, "native-image.json")));
            using var failedRecord = JsonDocument.Parse(File.ReadAllText(System.IO.Path.Combine(failedDirectory.FullName, "rehydration.json")));
            Assert.Equal("failed", failedRecord.RootElement.GetProperty("status").GetString());
            Assert.False(failedRecord.RootElement.TryGetProperty("nativeImageSha256", out _));
        }
        finally
        {
            failedDirectory.Delete(recursive: true);
        }
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void PublisherRejectsPartialOrMismatchedSuccessBindings()
    {
        var source = CreateSourceWithProgramHeaderSlot();
        var emitted = Emit(source);
        var result = GenericRehydrationEngine.Rehydrate(source, emitted.ArtifactBytes!, Options(source, emitted.Role!.RequestSha256));
        Assert.True(result.IsSuccess);
        using var directory = new TemporaryDirectory();
        var imagePath = directory.Path("native-image.bin");
        var rolePath = directory.Path("native-image.json");
        var recordPath = directory.Path("rehydration.json");
        File.WriteAllText(rolePath, "preexisting");

        var publication = RehydrationPublisher.Publish(result, imagePath, rolePath, recordPath);

        Assert.False(publication.Published);
        Assert.False(File.Exists(imagePath));
        Assert.Equal("preexisting", File.ReadAllText(rolePath));
        Assert.False(File.Exists(recordPath));
        Assert.Empty(Directory.GetFiles(directory.Root, "*.tmp", SearchOption.AllDirectories));
    }

    private static void AssertFailure(
        RehydrationOptions options,
        byte[] source,
        byte[] artifact,
        DiagnosticCode expectedCode)
    {
        var result = GenericRehydrationEngine.Rehydrate(source, artifact, options);
        Assert.False(result.IsSuccess);
        Assert.Null(result.NativeImage);
        Assert.Equal(RehydrationRecord.FailedStatus, result.Record.Status);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == expectedCode);
    }

    private static byte[] CreateSourceWithProgramHeaderSlot()
    {
        var bytes = File.ReadAllBytes(FixturePath);
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var relroIndex = parsed.File!.ProgramHeaders
            .Select((header, index) => (header, index))
            .Where(item => item.header.Type == ElfConstants.PtGnuRelro)
            .Select(item => item.index)
            .Single();
        var programHeaderOffset = checked(parsed.File.Header.ProgramHeaderOffset
            + checked((ulong)relroIndex * parsed.File.Header.ProgramHeaderEntrySize));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(checked((int)programHeaderOffset), sizeof(uint)),
            ElfConstants.PtNull);
        return bytes;
    }

    private static ProtectedImageEmissionResult Emit(byte[] source)
    {
        var request = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
            new[] { ProtectionPass.ControlFlowFlattening });
        var sourceHash = Sha256(source);
        var requestHash = ProtectedImageCodec.ComputeRequestSha256(request.Selectors, request.Passes);
        var options = new ProtectedImageProducerOptions(
            UnitId,
            ProtectedImageProfile.OuterExecveat,
            ProducerId,
            ProducerBuild,
            ConsumerId,
            sourceHash,
            requestHash);
        var result = new ProtectedImageProducer().Emit(source, request, options);
        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        return result;
    }

    private static RehydrationOptions Options(byte[] source, string requestHash) => new(
        Sha256(source),
        requestHash,
        UnitId,
        ProtectedImageProfile.OuterExecveat,
        ProducerId,
        ProducerBuild,
        ConsumerId,
        ConsumerBuild);

    private static string Sha256(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-rehydration-");

        public string Root => directory.FullName;

        public string Path(string name) => System.IO.Path.Combine(directory.FullName, name);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
