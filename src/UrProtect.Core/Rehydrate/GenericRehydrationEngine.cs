using System.Buffers.Binary;
using System.Diagnostics;
using System.Security.Cryptography;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Protect;

namespace UrProtect.Core.Rehydrate;

public static class RehydrationLimits
{
    public const int MaximumSourceBytes = 128 * 1024 * 1024;
    public const int MaximumNativeImageBytes = 128 * 1024 * 1024;
    public const int MaximumDiagnostics = 128;
    public const int MaximumDiagnosticMessageBytes = 4096;
    public const ulong PageAlignment = 4096;
}

public sealed record RehydrationOptions(
    string ExpectedSourceSha256,
    string ExpectedRequestSha256,
    string ExpectedUnitId,
    ProtectedImageProfile ExpectedProfile,
    string ExpectedProducerId,
    string ExpectedProducerBuildSha256,
    string ExpectedConsumerId,
    string ConsumerBuildSha256);

public sealed record NativeImageDescriptor(
    int SchemaVersion,
    string ArtifactRole,
    string AbiId,
    ushort AbiVersion,
    string Architecture,
    string UnitId,
    string Profile,
    string SourceSha256,
    string ProtectedImageSha256,
    string NativeImageSha256,
    long NativeImageSize,
    string ProducerId,
    string ProducerBuildSha256,
    string ConsumerId,
    string ConsumerBuildSha256,
    string RehydrationRecordSha256);

public sealed record NativeImage(
    byte[] Bytes,
    NativeImageDescriptor Descriptor,
    ElfFile ParsedImage);

public sealed record RehydrationRecord(
    int SchemaVersion,
    string Stage,
    string Status,
    string UnitId,
    string Profile,
    string AbiId,
    ushort AbiVersion,
    string Architecture,
    string SourceSha256,
    string RequestSha256,
    string ProtectedImageSha256,
    long ProtectedImageSize,
    string? NativeImageSha256,
    long? NativeImageSize,
    string ProducerId,
    string ProducerBuildSha256,
    string ConsumerId,
    string ConsumerBuildSha256,
    string LayoutStrategy,
    string HandoffRecordPath,
    string RawEvidenceManifestPath,
    string MaterializationStatus,
    long DurationMilliseconds,
    long? CpuMilliseconds,
    long? WorkingSetBytes,
    string? FirstFailureStage,
    IReadOnlyList<RehydrationDiagnostic> Diagnostics,
    string? HandoffRecordSha256 = null,
    string? HandoffStatus = null,
    string? PreHandoffRecordSha256 = null)
{
    public const int CurrentSchemaVersion = 1;
    public const string StageName = "rehydration";
    public const string PassedStatus = "passed";
    public const string FailedStatus = "failed";
    public const string CurrentLayoutStrategy = "append-executable-pt-load-v1";

    public bool IsPassed => string.Equals(Status, PassedStatus, StringComparison.Ordinal);
}

public sealed record RehydrationDiagnostic(string Severity, string Code, string Message, ulong? Offset)
{
    public static RehydrationDiagnostic From(Diagnostic diagnostic) =>
        new(diagnostic.Severity.ToString(), diagnostic.Code.ToString(), diagnostic.Message, diagnostic.Offset);
}

public sealed record RehydrationResult(
    NativeImage? NativeImage,
    RehydrationRecord Record,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => NativeImage is not null
        && Record.IsPassed
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

/// <summary>
/// Authenticates Protected Image v1 operation records and materializes their code
/// into a deterministic AArch64 Native Image. It never invokes a loader.
/// </summary>
public static class GenericRehydrationEngine
{
    public static RehydrationResult Rehydrate(
        ReadOnlyMemory<byte> source,
        ReadOnlyMemory<byte> protectedArtifact,
        RehydrationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var stopwatch = Stopwatch.StartNew();
        var process = Process.GetCurrentProcess();
        process.Refresh();
        var cpuBefore = process.TotalProcessorTime;
        var workingSetBefore = process.WorkingSet64;
        var diagnostics = new DiagnosticBag();
        var sourceSha256 = Sha256(source.Span);
        var protectedSha256 = Sha256(protectedArtifact.Span);
        var sourceBytes = source.Length <= RehydrationLimits.MaximumSourceBytes ? source.ToArray() : Array.Empty<byte>();
        var artifactBytes = protectedArtifact.Length <= ProtectedImageLimits.MaximumArtifactBytes
            ? protectedArtifact.ToArray()
            : Array.Empty<byte>();
        ProtectedImageDocument? document = null;
        byte[]? output = null;
        ElfFile? outputFile = null;

        ValidateOptions(options, diagnostics);
        if (source.Length is 0 or > RehydrationLimits.MaximumSourceBytes)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Source Image size is outside the rehydration bounds.");
        }

        if (protectedArtifact.Length is 0 or > ProtectedImageLimits.MaximumArtifactBytes)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image size is outside the rehydration bounds.");
        }

        if (!string.Equals(sourceSha256, NormalizeSha256(options.ExpectedSourceSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageSourceMismatch, "Source Image digest does not match the rehydration request.");
        }

        if (!diagnostics.HasErrors)
        {
            var decoded = ProtectedImageCodec.Decode(
                artifactBytes,
                options.ExpectedSourceSha256,
                options.ExpectedRequestSha256);
            diagnostics.AddRange(decoded.Diagnostics);
            document = decoded.Image;
        }

        if (document is not null)
        {
            ValidateIdentityBindings(document, options, diagnostics);
        }

        ElfFile? sourceFile = null;
        if (sourceBytes.Length > 0 && sourceBytes.Length <= RehydrationLimits.MaximumSourceBytes)
        {
            var parsedSource = ElfParser.Parse(sourceBytes);
            if (parsedSource.File is null || parsedSource.Diagnostics.Any(diagnostic => diagnostic.IsError))
            {
                diagnostics.AddRange(parsedSource.Diagnostics);
                diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Source Image did not pass bounded AArch64 ELF parsing.");
            }
            else
            {
                sourceFile = parsedSource.File;
            }
        }

        if (document is not null && sourceFile is not null && !diagnostics.HasErrors)
        {
            output = Materialize(sourceBytes, sourceFile, document, diagnostics);
            if (output is not null && !diagnostics.HasErrors)
            {
                var parsedOutput = ElfParser.Parse(output);
                diagnostics.AddRange(parsedOutput.Diagnostics);
                if (parsedOutput.File is null || parsedOutput.Diagnostics.Any(diagnostic => diagnostic.IsError))
                {
                    diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Materialized Native Image did not pass bounded AArch64 ELF parsing.");
                    output = null;
                }
                else if (!ValidateNativeImage(sourceFile, parsedOutput.File, output, diagnostics))
                {
                    output = null;
                }
                else
                {
                    outputFile = parsedOutput.File;
                }
            }
        }

        stopwatch.Stop();
        process.Refresh();
        var cpuMilliseconds = Math.Max(0, (long)(process.TotalProcessorTime - cpuBefore).TotalMilliseconds);
        var workingSetBytes = Math.Max(workingSetBefore, process.WorkingSet64);
        var success = output is not null && outputFile is not null && !diagnostics.HasErrors && document is not null;
        var record = CreateRecord(
            options,
            document,
            sourceSha256,
            protectedSha256,
            protectedArtifact.Length,
            success ? output : null,
            stopwatch.ElapsedMilliseconds,
            cpuMilliseconds,
            workingSetBytes,
            diagnostics);
        if (!success)
        {
            return new RehydrationResult(null, record, diagnostics.ToArray());
        }

        var nativeHash = Sha256(output!);
        var descriptor = new NativeImageDescriptor(
            1,
            "native-image",
            "urprotect.native-image.v1",
            1,
            ProtectedImageAbiV1.Architecture,
            document!.UnitId,
            document.Profile.ToCliValue(),
            sourceSha256,
            protectedSha256,
            nativeHash,
            output!.LongLength,
            document.ProducerId,
            document.ProducerBuildSha256,
            document.RehydratorConsumerId,
            NormalizeSha256(options.ConsumerBuildSha256),
            string.Empty);
        return new RehydrationResult(
            new NativeImage(output, descriptor, outputFile!),
            record,
            diagnostics.ToArray());
    }

    private static void ValidateOptions(RehydrationOptions options, DiagnosticBag diagnostics)
    {
        ValidateDigest(options.ExpectedSourceSha256, "expected source", diagnostics);
        ValidateDigest(options.ExpectedRequestSha256, "expected request", diagnostics);
        ValidateDigest(options.ExpectedProducerBuildSha256, "expected producer build", diagnostics);
        ValidateDigest(options.ConsumerBuildSha256, "consumer build", diagnostics);
        ValidateIdentity(options.ExpectedUnitId, "expected unit", diagnostics);
        ValidateIdentity(options.ExpectedProducerId, "expected producer", diagnostics);
        ValidateIdentity(options.ExpectedConsumerId, "expected consumer", diagnostics);
        if (options.ExpectedProfile is not (ProtectedImageProfile.OuterExecveat or ProtectedImageProfile.HostContextEntry))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "Expected Protected Image profile is unsupported.");
        }
    }

    private static void ValidateIdentityBindings(
        ProtectedImageDocument image,
        RehydrationOptions options,
        DiagnosticBag diagnostics)
    {
        if (!string.Equals(image.UnitId, options.ExpectedUnitId, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image unit identity does not match the rehydration request.");
        }

        if (image.Profile != options.ExpectedProfile)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageProfileMismatch, "Protected Image profile does not match the rehydration request.");
        }

        if (!string.Equals(image.ProducerId, options.ExpectedProducerId, StringComparison.Ordinal)
            || !string.Equals(image.ProducerBuildSha256, NormalizeSha256(options.ExpectedProducerBuildSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRoleMismatch, "Protected Image producer identity does not match the rehydration request.");
        }

        if (!string.Equals(image.RehydratorConsumerId, options.ExpectedConsumerId, StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageConsumerMismatch, "Protected Image consumer identity does not match the rehydration request.");
        }

        if (!string.Equals(image.RequestSha256, NormalizeSha256(options.ExpectedRequestSha256), StringComparison.Ordinal))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageRequestMismatch, "Protected Image request digest does not match the rehydration request.");
        }
    }

    private static byte[]? Materialize(
        byte[] source,
        ElfFile sourceFile,
        ProtectedImageDocument image,
        DiagnosticBag diagnostics)
    {
        if (image.Profile != ProtectedImageProfile.OuterExecveat)
        {
            diagnostics.Error(
                DiagnosticCode.RehydrationLayoutUnavailable,
                "The current Native Image materializer supports the outer-execveat layout only.");
            return null;
        }

        var regions = image.Operations.OfType<ProtectedImageEmitRegion>()
            .OrderBy(region => region.RegionId)
            .ToArray();
        var fixups = image.Operations.OfType<ProtectedImageEntryBranchFixup>()
            .OrderBy(fixup => fixup.SourceRegionId)
            .ThenBy(fixup => fixup.SourceOffset)
            .ToArray();
        if (regions.Length == 0 || fixups.Length != regions.Length)
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image operation stream is incomplete.");
            return null;
        }

        var regionById = regions.ToDictionary(region => region.RegionId);
        foreach (var region in regions)
        {
            var executableMappings = sourceFile.LoadMap.Segments
                .Where(segment => segment.IsExecutable
                    && segment.ContainsVirtualAddress(region.SourceAddress.Value, region.SourceSize))
                .ToArray();
            if (executableMappings.Length != 1
                || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(region.SourceAddress, region.SourceSize, out var fileOffset)
                || fileOffset.Value > (ulong)source.Length
                || region.SourceSize > (ulong)source.Length - fileOffset.Value)
            {
                diagnostics.Error(
                    DiagnosticCode.RehydrationLayoutUnavailable,
                    "An emitted region source range is not uniquely file-backed by an executable PT_LOAD.",
                    region.SourceAddress.Value);
            }
        }

        foreach (var fixup in fixups)
        {
            if (!regionById.TryGetValue(fixup.SourceRegionId, out var sourceRegion)
                || !regionById.TryGetValue(fixup.TargetRegionId, out var targetRegion)
                || fixup.SourceAddress != sourceRegion.SourceAddress
                || fixup.FixupKind != ProtectedImageFixupKind.Aarch64Branch26
                || !TryAdd(fixup.SourceAddress.Value, fixup.SourceOffset, out var branchAddress)
                || !sourceFile.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(branchAddress), sizeof(uint), out var branchFileOffset)
                || !sourceFile.LoadMap.Segments.Any(segment => segment.IsExecutable
                    && segment.ContainsVirtualAddress(branchAddress, sizeof(uint)))
                || branchFileOffset.Value > (ulong)source.Length - sizeof(uint))
            {
                diagnostics.Error(DiagnosticCode.RehydrationMalformed, "An entry fixup does not map to a bounded executable source instruction.", fixup.SourceAddress.Value);
            }
        }

        if (diagnostics.HasErrors)
        {
            return null;
        }

        var nullHeaderIndices = sourceFile.ProgramHeaders
            .Select((header, index) => (header, index))
            .Where(item => item.header.Type == ElfConstants.PtNull)
            .Select(item => item.index)
            .ToArray();
        if (nullHeaderIndices.Length == 0)
        {
            diagnostics.Error(
                DiagnosticCode.RehydrationLayoutUnavailable,
                "The source ELF has no PT_NULL program-header slot for a bounded appended executable region.");
            return null;
        }

        try
        {
            ulong codeSize = 0;
            foreach (var region in regions)
            {
                codeSize = checked(codeSize + (ulong)region.CodeBytes.Length);
            }

            if (codeSize == 0 || codeSize > ProtectedImageLimits.MaximumAggregateCodeBytes)
            {
                diagnostics.Error(DiagnosticCode.RehydrationMalformed, "Protected Image emitted code is empty or exceeds the aggregate materialization bound.");
                return null;
            }

            var fileOffset = AlignUp(checked((ulong)source.Length), RehydrationLimits.PageAlignment);
            var highestVirtualEnd = sourceFile.ProgramHeaders
                .Where(header => header.Type == ElfConstants.PtLoad)
                .Select(header => checked(header.VirtualAddress + header.MemorySize))
                .DefaultIfEmpty(0UL)
                .Max();
            var virtualAddress = AlignUp(highestVirtualEnd, RehydrationLimits.PageAlignment);
            var outputLength = checked(fileOffset + codeSize);
            if (outputLength > RehydrationLimits.MaximumNativeImageBytes || outputLength > int.MaxValue)
            {
                diagnostics.Error(DiagnosticCode.RehydrationLayoutUnavailable, "The deterministic appended Native Image exceeds its configured output bound.");
                return null;
            }

            var output = new byte[checked((int)outputLength)];
            source.CopyTo(output, 0);
            var regionAddresses = new Dictionary<uint, ulong>();
            var cursor = fileOffset;
            foreach (var region in regions)
            {
                regionAddresses.Add(region.RegionId, checked(virtualAddress + cursor - fileOffset));
                region.CodeBytes.CopyTo(output, checked((int)cursor));
                cursor = checked(cursor + (ulong)region.CodeBytes.Length);
            }

            foreach (var fixup in fixups)
            {
                var targetAddress = checked(regionAddresses[fixup.TargetRegionId] + fixup.TargetOffset);
                var branchAddress = checked(fixup.SourceAddress.Value + fixup.SourceOffset);
                if (!TryEncodeBranch26(branchAddress, targetAddress, out var branch))
                {
                    diagnostics.Error(
                        DiagnosticCode.RehydrationLayoutUnavailable,
                        "An AArch64 entry branch cannot reach its deterministic appended code region.",
                        branchAddress);
                    return null;
                }

                if (!sourceFile.LoadMap.TryVirtualAddressToFileOffset(new VirtualAddress(branchAddress), sizeof(uint), out var branchFileOffset)
                    || branchFileOffset.Value > int.MaxValue
                    || !TryAdd(branchFileOffset.Value, sizeof(uint), out var branchFileEnd)
                    || branchFileEnd > (ulong)output.Length)
                {
                    diagnostics.Error(DiagnosticCode.RehydrationMalformed, "An entry branch patch exceeds the Native Image bounds.", branchAddress);
                    return null;
                }

                BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(checked((int)branchFileOffset.Value), sizeof(uint)), branch);
            }

            var programHeaderOffset = checked(sourceFile.Header.ProgramHeaderOffset
                + checked((ulong)nullHeaderIndices[0] * sourceFile.Header.ProgramHeaderEntrySize));
            if (programHeaderOffset > int.MaxValue
                || !TryAdd(programHeaderOffset, ElfConstants.ProgramHeaderSize64, out var programHeaderEnd)
                || programHeaderEnd > (ulong)source.Length
                || fileOffset % RehydrationLimits.PageAlignment != virtualAddress % RehydrationLimits.PageAlignment)
            {
                diagnostics.Error(DiagnosticCode.RehydrationLayoutUnavailable, "The selected program-header slot or appended segment layout is not representable.");
                return null;
            }

            var programHeader = output.AsSpan(checked((int)programHeaderOffset), ElfConstants.ProgramHeaderSize64);
            programHeader.Clear();
            BinaryPrimitives.WriteUInt32LittleEndian(programHeader, ElfConstants.PtLoad);
            BinaryPrimitives.WriteUInt32LittleEndian(programHeader[4..], ElfConstants.PfR | ElfConstants.PfX);
            BinaryPrimitives.WriteUInt64LittleEndian(programHeader[8..], fileOffset);
            BinaryPrimitives.WriteUInt64LittleEndian(programHeader[16..], virtualAddress);
            BinaryPrimitives.WriteUInt64LittleEndian(programHeader[24..], virtualAddress);
            BinaryPrimitives.WriteUInt64LittleEndian(programHeader[32..], codeSize);
            BinaryPrimitives.WriteUInt64LittleEndian(programHeader[40..], codeSize);
            BinaryPrimitives.WriteUInt64LittleEndian(programHeader[48..], RehydrationLimits.PageAlignment);
            return output;
        }
        catch (OverflowException)
        {
            diagnostics.Error(DiagnosticCode.AddressOverflow, "Native Image layout arithmetic overflowed.");
            return null;
        }
    }

    private static bool ValidateNativeImage(
        ElfFile source,
        ElfFile native,
        byte[] output,
        DiagnosticBag diagnostics)
    {
        if (!native.Header.IsAarch64
            || native.Header.Type is not (ElfConstants.TypeDyn or ElfConstants.TypeExec)
            || output.Length is < ElfConstants.HeaderSize64 or > RehydrationLimits.MaximumNativeImageBytes
            || output.AsSpan().SequenceEqual(source.Bytes.Span))
        {
            diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Native Image identity, architecture, type, size, or distinctness validation failed.");
            return false;
        }

        var appended = native.ProgramHeaders.Where(header =>
            header.Type == ElfConstants.PtLoad
            && header.Flags == (ElfConstants.PfR | ElfConstants.PfX)
            && header.Alignment == RehydrationLimits.PageAlignment
            && header.FileSize > 0
            && header.FileSize == header.MemorySize
            && header.Offset >= (ulong)source.Bytes.Length).ToArray();
        if (appended.Length != 1)
        {
            diagnostics.Error(DiagnosticCode.NativeImageMalformed, "Native Image does not contain exactly one validated appended read-execute PT_LOAD.");
            return false;
        }

        return true;
    }

    private static RehydrationRecord CreateRecord(
        RehydrationOptions options,
        ProtectedImageDocument? image,
        string sourceSha256,
        string protectedImageSha256,
        long protectedImageSize,
        byte[]? nativeImage,
        long durationMilliseconds,
        long? cpuMilliseconds,
        long? workingSetBytes,
        DiagnosticBag diagnostics) =>
        new(
            RehydrationRecord.CurrentSchemaVersion,
            RehydrationRecord.StageName,
            diagnostics.HasErrors ? RehydrationRecord.FailedStatus : RehydrationRecord.PassedStatus,
            image?.UnitId ?? options.ExpectedUnitId,
            image?.Profile.ToCliValue() ?? options.ExpectedProfile.ToCliValue(),
            ProtectedImageAbiV1.AbiId,
            ProtectedImageAbiV1.AbiVersion,
            ProtectedImageAbiV1.Architecture,
            sourceSha256,
            image?.RequestSha256 ?? NormalizeSha256(options.ExpectedRequestSha256),
            protectedImageSha256,
            protectedImageSize,
            nativeImage is null ? null : Sha256(nativeImage),
            nativeImage?.LongLength,
            image?.ProducerId ?? options.ExpectedProducerId,
            image?.ProducerBuildSha256 ?? NormalizeSha256(options.ExpectedProducerBuildSha256),
            image?.RehydratorConsumerId ?? options.ExpectedConsumerId,
            NormalizeSha256(options.ConsumerBuildSha256),
            RehydrationRecord.CurrentLayoutStrategy,
            "handoff.json",
            "SHA256SUMS",
            diagnostics.HasErrors ? "failed" : "passed",
            durationMilliseconds,
            cpuMilliseconds,
            workingSetBytes,
            diagnostics.HasErrors ? RehydrationRecord.StageName : null,
            diagnostics.Take(RehydrationLimits.MaximumDiagnostics)
                .Select(RehydrationDiagnostic.From)
                .ToArray());

    private static bool TryEncodeBranch26(ulong source, ulong target, out uint encoding)
    {
        encoding = 0;
        if ((source & 3) != 0 || (target & 3) != 0)
        {
            return false;
        }

        long displacement;
        if (target >= source)
        {
            var delta = target - source;
            if (delta > long.MaxValue)
            {
                return false;
            }

            displacement = (long)delta;
        }
        else
        {
            var delta = source - target;
            if (delta > long.MaxValue)
            {
                return false;
            }

            displacement = -(long)delta;
        }

        if (displacement < -(128L * 1024 * 1024) || displacement >= 128L * 1024 * 1024)
        {
            return false;
        }

        encoding = 0x14000000u | (uint)((displacement >> 2) & 0x03FFFFFF);
        return true;
    }

    private static ulong AlignUp(ulong value, ulong alignment)
    {
        var remainder = value % alignment;
        return remainder == 0 ? value : checked(value + alignment - remainder);
    }

    private static bool TryAdd(ulong value, ulong length, out ulong result)
    {
        if (length > ulong.MaxValue - value)
        {
            result = 0;
            return false;
        }

        result = value + length;
        return true;
    }

    private static void ValidateDigest(string value, string label, DiagnosticBag diagnostics)
    {
        if (value is null || value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, $"The {label} SHA-256 binding is malformed.");
        }
    }

    private static void ValidateIdentity(string value, string label, DiagnosticBag diagnostics)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128
            || value.Any(character => !(char.IsAsciiLetterOrDigit(character) || character is '.' or '-' or '_' or '/' or ':')))
        {
            diagnostics.Error(DiagnosticCode.RehydrationMalformed, $"The {label} identity is outside the bounded format.");
        }
    }

    private static string NormalizeSha256(string value) => value is not null && value.Length == 64
        ? value.ToLowerInvariant()
        : string.Empty;

    private static string Sha256(ReadOnlySpan<byte> bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
}
