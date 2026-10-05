using System.Diagnostics;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;

namespace UrProtect.Core.Protect;

public enum ProtectedImageProfile : byte
{
    OuterExecveat = 1,
    HostContextEntry = 2,
}

public static class ProtectedImageProfileExtensions
{
    public static string ToCliValue(this ProtectedImageProfile profile) => profile switch
    {
        ProtectedImageProfile.OuterExecveat => "outer-execveat",
        ProtectedImageProfile.HostContextEntry => "host-context-entry",
        _ => profile.ToString(),
    };

    public static bool TryParse(string value, out ProtectedImageProfile profile)
    {
        profile = value switch
        {
            "outer-execveat" => ProtectedImageProfile.OuterExecveat,
            "host-context-entry" => ProtectedImageProfile.HostContextEntry,
            _ => default,
        };
        return value is "outer-execveat" or "host-context-entry";
    }
}

public enum ProtectedImageFixupKind : byte
{
    Aarch64Branch26 = 1,
}

public enum ProtectedImageOperationCode : byte
{
    EmitRegion = 1,
    ApplyEntryBranch26 = 2,
}

public abstract record ProtectedImageOperation(ProtectedImageOperationCode Code);

public sealed record ProtectedImageEmitRegion(
    uint RegionId,
    VirtualAddress SourceAddress,
    ulong SourceSize,
    byte[] CodeBytes)
    : ProtectedImageOperation(ProtectedImageOperationCode.EmitRegion);

public sealed record ProtectedImageEntryBranchFixup(
    uint SourceRegionId,
    uint TargetRegionId,
    VirtualAddress SourceAddress,
    uint SourceOffset,
    uint TargetOffset,
    ProtectedImageFixupKind FixupKind)
    : ProtectedImageOperation(ProtectedImageOperationCode.ApplyEntryBranch26);

public sealed record ProtectedImageDocument(
    string UnitId,
    ProtectedImageProfile Profile,
    string SourceSha256,
    string ProducerId,
    string ProducerBuildSha256,
    string RehydratorConsumerId,
    string RequestSha256,
    IReadOnlyList<string> Selectors,
    IReadOnlyList<ProtectionPass> Passes,
    IReadOnlyList<ProtectedImageOperation> Operations)
{
    public const ushort AbiVersion = 1;
    public const ushort Aarch64Architecture = ElfConstants.MachineAarch64;
    public const string MagicText = "UPPI";
}

public static class ProtectedImageLimits
{
    public const int MaximumArtifactBytes = 16 * 1024 * 1024;
    public const int MaximumOperations = 1024;
    public const int MaximumRegions = MaximumOperations / 2;
    public const int MaximumAggregateCodeBytes = 8 * 1024 * 1024;
    public const int MaximumUnitIdBytes = 128;
    public const int MaximumProducerIdBytes = 128;
    public const int MaximumConsumerIdBytes = 128;
    public const int MaximumSelectorCount = 64;
    public const int MaximumSelectorBytes = 256;
}

public sealed record ProtectedImageCodecResult(
    ProtectedImageDocument? Image,
    byte[]? ArtifactBytes,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => Diagnostics.All(diagnostic => !diagnostic.IsError)
        && (Image is not null || ArtifactBytes is not null);
}

/// <summary>Canonical, bounded encoder and decoder for the layout-neutral Protected Image ABI v1.</summary>
public static class ProtectedImageCodec
{
    private const int HeaderSize = 20;
    private const int DigestSize = 32;
    private const int OperationHeaderSize = 8;
    private const int MaximumRegionCodeBytes = 4 * 1024 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes(ProtectedImageDocument.MagicText);

    public static ProtectedImageCodecResult Encode(ProtectedImageDocument image)
    {
        ArgumentNullException.ThrowIfNull(image);
        var diagnostics = new DiagnosticBag();
        if (!ValidateDocument(image, diagnostics, requireCanonicalOperationOrder: true))
        {
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        try
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
            writer.Write(Magic);
            writer.Write(ProtectedImageDocument.AbiVersion);
            writer.Write(ProtectedImageDocument.Aarch64Architecture);
            writer.Write((byte)image.Profile);
            writer.Write(new byte[3]);
            writer.Write(0u); // Canonical total length is patched after encoding.
            writer.Write(checked((uint)image.Operations.Count));
            WriteDigest(writer, image.SourceSha256);
            WriteDigest(writer, image.ProducerBuildSha256);
            WriteDigest(writer, image.RequestSha256);
            WriteString(writer, image.UnitId, ProtectedImageLimits.MaximumUnitIdBytes);
            WriteString(writer, image.ProducerId, ProtectedImageLimits.MaximumProducerIdBytes);
            WriteString(writer, image.RehydratorConsumerId, ProtectedImageLimits.MaximumConsumerIdBytes);
            writer.Write(checked((ushort)image.Selectors.Count));
            foreach (var selector in image.Selectors)
            {
                WriteString(writer, selector, ProtectedImageLimits.MaximumSelectorBytes);
            }

            writer.Write(checked((byte)image.Passes.Count));
            foreach (var pass in image.Passes)
            {
                writer.Write((byte)pass);
            }

            foreach (var operation in image.Operations)
            {
                WriteOperation(writer, operation);
            }

            var totalLength = checked((int)stream.Length + DigestSize);
            if (totalLength > ProtectedImageLimits.MaximumArtifactBytes)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageLimitExceeded,
                    "Protected Image v1 exceeds the maximum artifact size.");
                return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
            }

            var bytes = stream.ToArray();
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, sizeof(uint)), checked((uint)totalLength));
            var artifactHash = SHA256.HashData(bytes);
            Array.Resize(ref bytes, totalLength);
            artifactHash.CopyTo(bytes.AsSpan(totalLength - DigestSize));
            return new ProtectedImageCodecResult(image, bytes, diagnostics.ToArray());
        }
        catch (Exception exception) when (exception is ArgumentException or EncoderFallbackException or OverflowException)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageMalformed,
                "Protected Image v1 could not be encoded within its bounded canonical representation.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }
    }

    public static ProtectedImageCodecResult Decode(
        ReadOnlyMemory<byte> artifactBytes,
        string? expectedSourceSha256 = null,
        string? expectedRequestSha256 = null)
    {
        var diagnostics = new DiagnosticBag();
        if (artifactBytes.Length < HeaderSize + DigestSize
            || artifactBytes.Length > ProtectedImageLimits.MaximumArtifactBytes)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image v1 length is outside the supported bounds.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        var reader = new BoundedReader(artifactBytes);
        var bytes = artifactBytes.Span;
        if (!bytes[..Magic.Length].SequenceEqual(Magic))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageMalformed,
                "Protected Image v1 magic is invalid; the artifact is not a Protected Image ABI record.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        var storedDigest = bytes[^DigestSize..];
        var computedDigest = SHA256.HashData(bytes[..^DigestSize]);
        if (!CryptographicOperations.FixedTimeEquals(storedDigest, computedDigest))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageIntegrityMismatch,
                "Protected Image v1 canonical digest does not match its artifact bytes.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        if (!reader.TryReadUInt16(4, out var version)
            || !reader.TryReadUInt16(6, out var architecture)
            || !reader.TryReadByte(8, out var profileValue)
            || !reader.TrySlice(9, 3, out var reserved)
            || !reader.TryReadUInt32(12, out var declaredLength)
            || !reader.TryReadUInt32(16, out var operationCount))
        {
            return Malformed("Protected Image v1 header is truncated.");
        }

        if (version != ProtectedImageDocument.AbiVersion)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageUnsupported,
                $"Protected Image ABI version {version} is unsupported.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        if (architecture != ProtectedImageDocument.Aarch64Architecture)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageUnsupported,
                $"Protected Image architecture identifier {architecture} is unsupported.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        if (profileValue is not (byte)ProtectedImageProfile.OuterExecveat
            and not (byte)ProtectedImageProfile.HostContextEntry)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageUnsupported,
                $"Protected Image profile identifier {profileValue} is unsupported.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        if (reserved.Span.IndexOfAnyExcept((byte)0) >= 0)
        {
            return Malformed("Protected Image v1 reserved header bytes must be zero.");
        }

        if (declaredLength != artifactBytes.Length
            || operationCount > (uint)ProtectedImageLimits.MaximumOperations)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image v1 declared length or operation count is outside the supported bounds.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        ulong cursor = HeaderSize;
        if (!TryReadDigest(reader, ref cursor, out var sourceSha256)
            || !TryReadDigest(reader, ref cursor, out var producerBuildSha256)
            || !TryReadDigest(reader, ref cursor, out var requestSha256)
            || !TryReadString(reader, ref cursor, ProtectedImageLimits.MaximumUnitIdBytes, out var unitId)
            || !TryReadString(reader, ref cursor, ProtectedImageLimits.MaximumProducerIdBytes, out var producerId)
            || !TryReadString(reader, ref cursor, ProtectedImageLimits.MaximumConsumerIdBytes, out var consumerId)
            || !reader.TryReadUInt16(cursor, out var selectorCount))
        {
            return Malformed("Protected Image v1 identity or request metadata is truncated.");
        }

        cursor = checked(cursor + sizeof(ushort));
        if (selectorCount is 0 or > ProtectedImageLimits.MaximumSelectorCount)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image v1 selector count is outside the supported bounds.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        var selectors = new List<string>(selectorCount);
        for (var index = 0; index < selectorCount; index++)
        {
            if (!TryReadString(reader, ref cursor, ProtectedImageLimits.MaximumSelectorBytes, out var selector))
            {
                return Malformed("Protected Image v1 selector metadata is truncated or invalid UTF-8.");
            }

            selectors.Add(selector);
        }

        if (!reader.TryReadByte(cursor, out var passCount))
        {
            return Malformed("Protected Image v1 pass metadata is truncated.");
        }

        cursor = checked(cursor + 1);
        if (passCount is 0 or > 2 || !reader.TrySlice(cursor, passCount, out var encodedPasses))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "Protected Image v1 pass count is outside the supported bounds.");
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        cursor = checked(cursor + passCount);
        var passes = new List<ProtectionPass>(passCount);
        foreach (var encodedPass in encodedPasses.Span)
        {
            if (encodedPass is not (byte)ProtectionPass.ControlFlowFlattening
                and not (byte)ProtectionPass.RegisterPermutation)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageUnsupported,
                    $"Protected Image transformation pass identifier {encodedPass} is unsupported.");
                return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
            }

            passes.Add((ProtectionPass)encodedPass);
        }

        var operations = new List<ProtectedImageOperation>(checked((int)operationCount));
        var operationEnd = (ulong)artifactBytes.Length - DigestSize;
        for (uint index = 0; index < operationCount; index++)
        {
            if (!reader.TryReadByte(cursor, out var codeValue)
                || !reader.TrySlice(checked(cursor + 1), 3, out var opReserved)
                || !reader.TryReadUInt32(checked(cursor + 4), out var recordSize))
            {
                return Malformed("Protected Image v1 operation header is truncated.");
            }

            if (opReserved.Span.IndexOfAnyExcept((byte)0) >= 0
                || recordSize < (uint)OperationHeaderSize
                || cursor > operationEnd
                || recordSize > operationEnd - cursor)
            {
                return Malformed("Protected Image v1 operation record length or reserved bytes are invalid.");
            }

            var recordEnd = checked(cursor + recordSize);
            var body = checked(cursor + (ulong)OperationHeaderSize);
            if (codeValue == (byte)ProtectedImageOperationCode.EmitRegion)
            {
                if (!reader.TryReadUInt32(body, out var regionId)
                    || !reader.TryReadUInt64(checked(body + 4), out var sourceAddress)
                    || !reader.TryReadUInt64(checked(body + 12), out var sourceSize)
                    || !reader.TryReadUInt32(checked(body + 20), out var codeLength)
                    || codeLength > MaximumRegionCodeBytes
                    || !reader.TrySlice(checked(body + 24), codeLength, out var codeBytes)
                    || checked(body + 24 + codeLength) != recordEnd)
                {
                    return Malformed("Protected Image v1 emitted-region operation is truncated or oversized.");
                }

                operations.Add(new ProtectedImageEmitRegion(
                    regionId,
                    new VirtualAddress(sourceAddress),
                    sourceSize,
                    codeBytes.ToArray()));
            }
            else if (codeValue == (byte)ProtectedImageOperationCode.ApplyEntryBranch26)
            {
                if (!reader.TryReadUInt32(body, out var sourceRegionId)
                    || !reader.TryReadUInt32(checked(body + 4), out var targetRegionId)
                    || !reader.TryReadUInt64(checked(body + 8), out var sourceAddress)
                    || !reader.TryReadUInt32(checked(body + 16), out var sourceOffset)
                    || !reader.TryReadUInt32(checked(body + 20), out var targetOffset)
                    || !reader.TryReadByte(checked(body + 24), out var fixupKind)
                    || !reader.TrySlice(checked(body + 25), 3, out var fixupReserved)
                    || checked(body + 28) != recordEnd)
                {
                    return Malformed("Protected Image v1 entry-fixup operation is truncated or has an invalid length.");
                }

                if (fixupReserved.Span.IndexOfAnyExcept((byte)0) >= 0
                    || fixupKind != (byte)ProtectedImageFixupKind.Aarch64Branch26)
                {
                    diagnostics.Error(
                        DiagnosticCode.ProtectedImageUnsupported,
                        "Protected Image v1 entry-fixup kind or reserved bytes are unsupported.");
                    return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
                }

                operations.Add(new ProtectedImageEntryBranchFixup(
                    sourceRegionId,
                    targetRegionId,
                    new VirtualAddress(sourceAddress),
                    sourceOffset,
                    targetOffset,
                    (ProtectedImageFixupKind)fixupKind));
            }
            else
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageUnsupported,
                    $"Protected Image operation identifier {codeValue} is unsupported.");
                return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
            }

            cursor = recordEnd;
        }

        if (cursor != operationEnd)
        {
            return Malformed("Protected Image v1 contains trailing or unclaimed operation bytes.");
        }

        var image = new ProtectedImageDocument(
            unitId,
            (ProtectedImageProfile)profileValue,
            sourceSha256,
            producerId,
            producerBuildSha256,
            consumerId,
            requestSha256,
            selectors,
            passes,
            operations);
        if (!ValidateDocument(image, diagnostics, requireCanonicalOperationOrder: true))
        {
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }

        if (expectedSourceSha256 is not null
            && !string.Equals(NormalizeSha256(expectedSourceSha256), image.SourceSha256, StringComparison.Ordinal))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageSourceMismatch,
                "Protected Image source digest does not match the requested source image.");
        }

        if (expectedRequestSha256 is not null
            && !string.Equals(NormalizeSha256(expectedRequestSha256), image.RequestSha256, StringComparison.Ordinal))
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageRequestMismatch,
                "Protected Image request digest does not match the requested transformation.");
        }

        return diagnostics.HasErrors
            ? new ProtectedImageCodecResult(null, null, diagnostics.ToArray())
            : new ProtectedImageCodecResult(image, artifactBytes.ToArray(), diagnostics.ToArray());

        ProtectedImageCodecResult Malformed(string message)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, message);
            return new ProtectedImageCodecResult(null, null, diagnostics.ToArray());
        }
    }

    public static string ComputeRequestSha256(
        IReadOnlyList<FunctionSelector> selectors,
        IReadOnlyList<ProtectionPass> passes)
    {
        ArgumentNullException.ThrowIfNull(selectors);
        ArgumentNullException.ThrowIfNull(passes);
        return ComputeRequestSha256(
            selectors.Select(selector => selector.ToDisplayString()).ToArray(),
            passes);
    }

    public static string ComputeRequestSha256(
        IReadOnlyList<string> selectors,
        IReadOnlyList<ProtectionPass> passes)
    {
        ArgumentNullException.ThrowIfNull(selectors);
        ArgumentNullException.ThrowIfNull(passes);
        if (selectors.Count is 0 or > ProtectedImageLimits.MaximumSelectorCount)
        {
            throw new ArgumentException("Protected Image request selector count is outside the supported bounds.", nameof(selectors));
        }

        if (passes.Count is 0 or > 2)
        {
            throw new ArgumentException("Protected Image request pass count is outside the supported bounds.", nameof(passes));
        }

        if (passes.Any(pass => pass is not (
                ProtectionPass.ControlFlowFlattening
                or ProtectionPass.RegisterPermutation)))
        {
            throw new ArgumentException("Protected Image request contains an unsupported pass.", nameof(passes));
        }

        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(Encoding.ASCII.GetBytes("URP-PROTECTION-REQUEST-V1\0"));
        writer.Write(checked((ushort)selectors.Count));
        foreach (var selector in selectors)
        {
            WriteString(writer, selector, ProtectedImageLimits.MaximumSelectorBytes);
        }

        var orderedPasses = ProtectionPassOrdering.Normalize(passes);
        writer.Write(checked((byte)orderedPasses.Count));
        foreach (var pass in orderedPasses)
        {
            writer.Write((byte)pass);
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static bool ValidateDocument(
        ProtectedImageDocument image,
        DiagnosticBag diagnostics,
        bool requireCanonicalOperationOrder = false)
    {
        var valid = true;
        if (image.Profile is not (ProtectedImageProfile.OuterExecveat or ProtectedImageProfile.HostContextEntry))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageUnsupported, "Protected Image profile is unsupported.");
            valid = false;
        }

        valid &= ValidateId(image.UnitId, ProtectedImageLimits.MaximumUnitIdBytes, "unit", diagnostics);
        valid &= ValidateId(image.ProducerId, ProtectedImageLimits.MaximumProducerIdBytes, "producer", diagnostics);
        valid &= ValidateId(image.RehydratorConsumerId, ProtectedImageLimits.MaximumConsumerIdBytes, "rehydrator consumer", diagnostics);
        valid &= ValidateSha256(image.SourceSha256, "source", diagnostics);
        valid &= ValidateSha256(image.ProducerBuildSha256, "producer build", diagnostics);
        valid &= ValidateSha256(image.RequestSha256, "request", diagnostics);

        if (image.Selectors is not null
            && image.Passes is not null
            && image.Selectors.Count is > 0 and <= ProtectedImageLimits.MaximumSelectorCount
            && image.Passes.Count is > 0 and <= 2)
        {
            try
            {
                var expectedRequestSha256 = ComputeRequestSha256(image.Selectors, image.Passes);
                if (!string.Equals(expectedRequestSha256, image.RequestSha256, StringComparison.OrdinalIgnoreCase))
                {
                    diagnostics.Error(
                        DiagnosticCode.ProtectedImageRequestMismatch,
                        "Protected Image request digest is not bound to its selectors and pass order.");
                    valid = false;
                }
            }
            catch (ArgumentException)
            {
                diagnostics.Error(
                    DiagnosticCode.ProtectedImageMalformed,
                    "Protected Image request metadata cannot be represented by the bounded request codec.");
                valid = false;
            }
        }

        if (image.Selectors is null || image.Selectors.Count is 0 or > ProtectedImageLimits.MaximumSelectorCount)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image selector count is outside the supported bounds.");
            valid = false;
        }
        else
        {
            foreach (var selector in image.Selectors)
            {
                valid &= ValidateString(selector, ProtectedImageLimits.MaximumSelectorBytes, "selector", diagnostics);
            }
        }

        if (image.Passes is null || image.Passes.Count is 0 or > 2)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image pass count is outside the supported bounds.");
            valid = false;
        }
        else
        {
            var ordered = ProtectionPassOrdering.Normalize(image.Passes);
            if (ordered.Count != image.Passes.Count || !ordered.SequenceEqual(image.Passes))
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image passes must be unique and in canonical transform order.");
                valid = false;
            }
        }

        if (image.Operations is null
            || image.Operations.Count is < 2 or > ProtectedImageLimits.MaximumOperations
            || image.Operations.Count % 2 != 0)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image operation count is outside the supported bounds.");
            return false;
        }

        var regions = new Dictionary<uint, ProtectedImageEmitRegion>();
        var fixups = new List<ProtectedImageEntryBranchFixup>();
        var sourceRanges = new List<(ulong Start, ulong End)>();
        var codeBytes = 0;
        foreach (var operation in image.Operations)
        {
            switch (operation)
            {
                case ProtectedImageEmitRegion region:
                    if (region.RegionId == 0 || regions.ContainsKey(region.RegionId))
                    {
                        diagnostics.Error(DiagnosticCode.ProtectedImageDuplicateRecord, "Protected Image contains a duplicate or zero region ID.");
                        valid = false;
                        continue;
                    }

                    if (region.SourceSize < sizeof(uint)
                        || (region.SourceAddress.Value & 3) != 0
                        || (region.SourceSize & 3) != 0
                        || !TryAdd(region.SourceAddress.Value, region.SourceSize, out var end)
                        || region.CodeBytes is null
                        || region.CodeBytes.Length < sizeof(uint)
                        || region.CodeBytes.Length > MaximumRegionCodeBytes
                        || (region.CodeBytes.Length & 3) != 0)
                    {
                        diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image region range or code length is invalid.");
                        valid = false;
                        continue;
                    }

                    if (region.CodeBytes.Length > ProtectedImageLimits.MaximumAggregateCodeBytes - codeBytes)
                    {
                        diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image aggregate code bytes exceed the supported bound.");
                        valid = false;
                    }
                    else
                    {
                        codeBytes += region.CodeBytes.Length;
                    }

                    if (codeBytes > ProtectedImageLimits.MaximumAggregateCodeBytes)
                    {
                        diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, "Protected Image aggregate code bytes exceed the supported bound.");
                        valid = false;
                    }

                    if (sourceRanges.Any(range => region.SourceAddress.Value < range.End && range.Start < end))
                    {
                        diagnostics.Error(DiagnosticCode.ProtectedImageOverlap, "Protected Image source regions overlap.");
                        valid = false;
                    }

                    sourceRanges.Add((region.SourceAddress.Value, end));
                    regions.Add(region.RegionId, region);
                    break;
                case ProtectedImageEntryBranchFixup fixup:
                    if (fixup.FixupKind != ProtectedImageFixupKind.Aarch64Branch26)
                    {
                        diagnostics.Error(DiagnosticCode.ProtectedImageUnsupported, "Protected Image entry-fixup kind is unsupported.");
                        valid = false;
                    }

                    fixups.Add(fixup);
                    break;
                default:
                    diagnostics.Error(DiagnosticCode.ProtectedImageUnsupported, "Protected Image operation type is unsupported.");
                    valid = false;
                    break;
            }
        }

        if (regions.Count == 0 || regions.Count != fixups.Count)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Each Protected Image code region must have exactly one entry fixup.");
            valid = false;
        }

        var fixedSourceRegions = new HashSet<uint>();
        var fixupSites = new HashSet<(uint RegionId, uint Offset)>();
        foreach (var fixup in fixups)
        {
            if (!regions.TryGetValue(fixup.SourceRegionId, out var sourceRegion)
                || !regions.TryGetValue(fixup.TargetRegionId, out var targetRegion))
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image fixup references an unknown region.");
                valid = false;
                continue;
            }

            if (!fixedSourceRegions.Add(fixup.SourceRegionId)
                || !fixupSites.Add((fixup.SourceRegionId, fixup.SourceOffset)))
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageDuplicateRecord, "Protected Image contains a duplicate entry fixup.");
                valid = false;
            }

            if (fixup.SourceAddress != sourceRegion.SourceAddress
                || fixup.SourceOffset > sourceRegion.SourceSize
                || sourceRegion.SourceSize - fixup.SourceOffset < sizeof(uint)
                || (fixup.SourceOffset & 3) != 0
                || fixup.TargetOffset >= targetRegion.CodeBytes.Length
                || (fixup.TargetOffset & 3) != 0)
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image entry fixup range or target offset is invalid.");
                valid = false;
            }
        }

        if (fixedSourceRegions.Count != regions.Count)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image has an unbound code region.");
            valid = false;
        }

        if (requireCanonicalOperationOrder)
        {
            var canonical = image.Operations
                .OrderBy(operation => operation switch
                {
                    ProtectedImageEmitRegion region => region.RegionId,
                    ProtectedImageEntryBranchFixup fixup => fixup.SourceRegionId,
                    _ => uint.MaxValue,
                })
                .ThenBy(operation => operation.Code)
                .ToArray();
            if (!canonical.SequenceEqual(image.Operations))
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, "Protected Image operations are not in canonical order.");
                valid = false;
            }
        }

        return valid && !diagnostics.HasErrors;
    }

    private static bool ValidateId(string? value, int maximumBytes, string label, DiagnosticBag diagnostics)
    {
        if (!ValidateString(value, maximumBytes, label, diagnostics))
        {
            return false;
        }

        if (value!.Any(character => !(char.IsAsciiLetterOrDigit(character)
            || character is '.' or '-' or '_' or '/' or ':')))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image {label} ID contains unsupported characters.");
            return false;
        }

        return true;
    }

    private static bool ValidateString(string? value, int maximumBytes, string label, DiagnosticBag diagnostics)
    {
        if (string.IsNullOrEmpty(value))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image {label} must not be empty.");
            return false;
        }

        try
        {
            var length = StrictUtf8.GetByteCount(value);
            if (length > maximumBytes)
            {
                diagnostics.Error(DiagnosticCode.ProtectedImageLimitExceeded, $"Protected Image {label} exceeds its UTF-8 byte limit.");
                return false;
            }
        }
        catch (EncoderFallbackException)
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image {label} is not valid UTF-8.");
            return false;
        }

        return true;
    }

    private static bool ValidateSha256(string? value, string label, DiagnosticBag diagnostics)
    {
        if (value is null || value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            diagnostics.Error(DiagnosticCode.ProtectedImageMalformed, $"Protected Image {label} SHA-256 must contain exactly 64 hexadecimal characters.");
            return false;
        }

        return true;
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

    private static string NormalizeSha256(string value) => value.Length == 64
        ? value.ToLowerInvariant()
        : string.Empty;

    private static void WriteDigest(BinaryWriter writer, string value) =>
        writer.Write(Convert.FromHexString(value));

    private static void WriteString(BinaryWriter writer, string value, int maximumBytes)
    {
        var encoded = StrictUtf8.GetBytes(value);
        if (encoded.Length > maximumBytes || encoded.Length > ushort.MaxValue)
        {
            throw new ArgumentException("Protected Image string exceeds its configured bound.", nameof(value));
        }

        writer.Write(checked((ushort)encoded.Length));
        writer.Write(encoded);
    }

    private static bool TryReadDigest(BoundedReader reader, ref ulong cursor, out string value)
    {
        value = string.Empty;
        if (!reader.TrySlice(cursor, DigestSize, out var bytes))
        {
            return false;
        }

        cursor = checked(cursor + DigestSize);
        value = Convert.ToHexString(bytes.Span).ToLowerInvariant();
        return true;
    }

    private static bool TryReadString(BoundedReader reader, ref ulong cursor, int maximumBytes, out string value)
    {
        value = string.Empty;
        if (!reader.TryReadUInt16(cursor, out var length) || length == 0 || length > maximumBytes)
        {
            return false;
        }

        cursor = checked(cursor + sizeof(ushort));
        if (!reader.TrySlice(cursor, length, out var encoded))
        {
            return false;
        }

        try
        {
            value = StrictUtf8.GetString(encoded.Span);
        }
        catch (DecoderFallbackException)
        {
            return false;
        }

        cursor = checked(cursor + length);
        return true;
    }

    private static void WriteOperation(BinaryWriter writer, ProtectedImageOperation operation)
    {
        var recordStart = writer.BaseStream.Position;
        writer.Write((byte)operation.Code);
        writer.Write(new byte[3]);
        writer.Write(0u); // Record size is patched once the typed body is complete.
        switch (operation)
        {
            case ProtectedImageEmitRegion region:
                writer.Write(region.RegionId);
                writer.Write(region.SourceAddress.Value);
                writer.Write(region.SourceSize);
                writer.Write(checked((uint)region.CodeBytes.Length));
                writer.Write(region.CodeBytes);
                break;
            case ProtectedImageEntryBranchFixup fixup:
                writer.Write(fixup.SourceRegionId);
                writer.Write(fixup.TargetRegionId);
                writer.Write(fixup.SourceAddress.Value);
                writer.Write(fixup.SourceOffset);
                writer.Write(fixup.TargetOffset);
                writer.Write((byte)fixup.FixupKind);
                writer.Write(new byte[3]);
                break;
            default:
                throw new ArgumentException("Unknown Protected Image operation type.", nameof(operation));
        }

        var recordSize = checked((uint)(writer.BaseStream.Position - recordStart));
        writer.BaseStream.Position = recordStart + 4;
        writer.Write(recordSize);
        writer.BaseStream.Position = recordStart + recordSize;
    }
}
