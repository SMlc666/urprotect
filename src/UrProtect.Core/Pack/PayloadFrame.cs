using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Pack;

public enum PayloadCompression : uint
{
    Deflate = 1,
}

public sealed record PayloadFrameLimits(
    ulong MaximumSourceBytes = 256UL * 1024 * 1024,
    ulong MaximumEncodedBytes = 256UL * 1024 * 1024,
    ulong MaximumWrapperBytes = 512UL * 1024 * 1024,
    ulong MaximumSourceNameBytes = 4096,
    ulong MaximumEntryNameBytes = HostContextContract.MaximumEntryNameBytes);

public sealed record PayloadFrameEncoding(
    byte[] FrameBytes,
    ulong SourceSize,
    ulong EncodedSize,
    byte[] SourceSha256,
    byte[] EncodedSha256,
    string SourceName,
    PayloadCompression Compression)
{
    public string SourceSha256Hex => Convert.ToHexString(SourceSha256).ToLowerInvariant();

    public string EncodedSha256Hex => Convert.ToHexString(EncodedSha256).ToLowerInvariant();

    public ushort FrameVersion { get; init; } = PayloadFrameCodec.FormatVersion;

    public HostContextFrameMetadata? HostContextMetadata { get; init; }
}

public sealed record PayloadFrameDecodeResult(
    byte[]? SourceBytes,
    ulong SourceSize,
    ulong EncodedSize,
    byte[]? SourceSha256,
    byte[]? EncodedSha256,
    string? SourceName,
    PayloadCompression? Compression,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => SourceBytes is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);

    public ushort FrameVersion { get; init; }

    public HostContextFrameMetadata? HostContextMetadata { get; init; }
}

public sealed record WrapperPayloadResult(
    byte[]? SourceBytes,
    ulong FrameOffset,
    ulong FrameLength,
    PayloadFrameDecodeResult? Frame,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public bool IsSuccess => SourceBytes is not null && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public static class PayloadFrameCodec
{
    public const ushort FormatVersion = 1;
    public const ushort HostContextFormatVersion = 2;
    public const ushort LauncherAbiVersion = LauncherContract.AbiVersion;
    public const ushort HeaderSize = 112;
    public const ushort HostContextHeaderSize = 136;
    public const int HostContextAbiVersionOffset = 112;
    public const int HostContextReservedBeforeCapabilitiesOffset = 116;
    public const int HostContextRequiredCapabilitiesOffset = 120;
    public const int HostContextEntryNameSizeOffset = 128;
    public const int HostContextReservedAfterEntryNameSizeOffset = 132;
    public const int TrailerSize = 24;
    public const uint DeflateFlag = (uint)PayloadCompression.Deflate;
    public const int Sha256Size = 32;

    private static readonly byte[] HeaderMagic = "URPCK01\0"u8.ToArray();
    private static readonly byte[] TrailerMagic = "URTRAIL1"u8.ToArray();
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);

    public static bool TryEncode(
        ReadOnlySpan<byte> source,
        ulong frameOffset,
        PayloadCompression compression,
        PayloadFrameLimits limits,
        string sourceName,
        out PayloadFrameEncoding? encoding,
        out IReadOnlyList<Diagnostic> diagnostics)
        => TryEncodeCore(
            source,
            frameOffset,
            compression,
            limits,
            sourceName,
            hostContextMetadata: null,
            out encoding,
            out diagnostics);

    public static bool TryEncodeHostContext(
        ReadOnlySpan<byte> source,
        ulong frameOffset,
        PayloadCompression compression,
        PayloadFrameLimits limits,
        string sourceName,
        HostContextFrameMetadata hostContextMetadata,
        out PayloadFrameEncoding? encoding,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(hostContextMetadata);
        return TryEncodeCore(
            source,
            frameOffset,
            compression,
            limits,
            sourceName,
            hostContextMetadata,
            out encoding,
            out diagnostics);
    }

    private static bool TryEncodeCore(
        ReadOnlySpan<byte> source,
        ulong frameOffset,
        PayloadCompression compression,
        PayloadFrameLimits limits,
        string sourceName,
        HostContextFrameMetadata? hostContextMetadata,
        out PayloadFrameEncoding? encoding,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(limits);
        var errors = new DiagnosticBag();
        encoding = null;

        if (!TryEncodeSourceName(sourceName, limits.MaximumSourceNameBytes, out var sourceNameBytes))
        {
            errors.Error(DiagnosticCode.PayloadMalformed, "The source argv[0] name is invalid or exceeds its limit.");
            diagnostics = errors.ToArray();
            return false;
        }

        byte[] entryNameBytes = Array.Empty<byte>();
        if (hostContextMetadata is not null)
        {
            if (!hostContextMetadata.IsValid(out var metadataError))
            {
                var unsupported = !HostContextContract.IsSupportedVersion(hostContextMetadata.AbiVersion)
                    || !HostContextContract.HasRequiredCapabilities(
                        hostContextMetadata.RequiredCapabilities,
                        HostContextContract.MandatoryCapabilities)
                    || !HostContextContract.HasOnlySupportedCapabilities(
                        hostContextMetadata.RequiredCapabilities);
                errors.Error(
                    unsupported ? DiagnosticCode.PayloadUnsupported : DiagnosticCode.PayloadMalformed,
                    metadataError ?? "The HostContext frame metadata is invalid.");
                diagnostics = errors.ToArray();
                return false;
            }

            try
            {
                entryNameBytes = StrictUtf8.GetBytes(hostContextMetadata.EntryName);
            }
            catch (EncoderFallbackException)
            {
                errors.Error(DiagnosticCode.PayloadMalformed, "The HostContext entry name is not valid UTF-8.");
                diagnostics = errors.ToArray();
                return false;
            }

            if ((ulong)entryNameBytes.Length > limits.MaximumEntryNameBytes)
            {
                errors.Error(DiagnosticCode.PayloadLimitExceeded, "The HostContext entry name exceeds the configured limit.");
                diagnostics = errors.ToArray();
                return false;
            }
        }

        if (compression != PayloadCompression.Deflate)
        {
            errors.Error(
                DiagnosticCode.PayloadUnsupported,
                $"Payload compression {compression} is not supported.");
            diagnostics = errors.ToArray();
            return false;
        }

        if ((ulong)source.Length > limits.MaximumSourceBytes)
        {
            errors.Error(
                DiagnosticCode.PayloadLimitExceeded,
                $"The source ELF is larger than the configured limit of {limits.MaximumSourceBytes} bytes.");
            diagnostics = errors.ToArray();
            return false;
        }

        byte[] encoded;
        try
        {
            using var compressed = new MemoryStream();
            using (var deflate = new DeflateStream(compressed, CompressionLevel.Optimal, leaveOpen: true))
            {
                deflate.Write(source);
            }

            encoded = compressed.ToArray();
        }
        catch (Exception exception) when (exception is IOException or ArgumentException)
        {
            errors.Error(DiagnosticCode.PayloadMalformed, $"The payload could not be compressed: {exception.Message}");
            diagnostics = errors.ToArray();
            return false;
        }

        if ((ulong)encoded.Length > limits.MaximumEncodedBytes)
        {
            errors.Error(
                DiagnosticCode.PayloadLimitExceeded,
                $"The compressed payload is larger than the configured limit of {limits.MaximumEncodedBytes} bytes.");
            diagnostics = errors.ToArray();
            return false;
        }

        var headerSize = hostContextMetadata is null ? HeaderSize : HostContextHeaderSize;
        if (!TryCheckedAdd((ulong)headerSize, (ulong)sourceNameBytes.Length, out var entryNameOffset)
            || !TryCheckedAdd(entryNameOffset, (ulong)entryNameBytes.Length, out var encodedOffsetWithinFrame)
            || !TryCheckedAdd(frameOffset, encodedOffsetWithinFrame, out var payloadOffset)
            || !TryCheckedAdd(payloadOffset, (ulong)encoded.Length, out var frameEnd)
            || !TryCheckedAdd(frameEnd, TrailerSize, out var wrapperSize)
            || wrapperSize > limits.MaximumWrapperBytes
            || !TryCheckedAdd(encodedOffsetWithinFrame, (ulong)encoded.Length, out var frameLength)
            || frameLength > int.MaxValue)
        {
            errors.Error(
                DiagnosticCode.PayloadLimitExceeded,
                "The wrapper size or payload offset exceeds the configured bounds.");
            diagnostics = errors.ToArray();
            return false;
        }

        var sourceHash = SHA256.HashData(source);
        var encodedHash = SHA256.HashData(encoded);
        var frame = new byte[checked((int)frameLength)];
        var header = frame.AsSpan(0, headerSize);
        HeaderMagic.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(
            header[8..10],
            hostContextMetadata is null ? FormatVersion : HostContextFormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[10..12], headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..16], (uint)compression);
        BinaryPrimitives.WriteUInt16LittleEndian(header[16..18], Elf.ElfConstants.MachineAarch64);
        BinaryPrimitives.WriteUInt16LittleEndian(header[18..20], Elf.ElfConstants.TypeDyn);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..24], checked((uint)sourceNameBytes.Length));
        BinaryPrimitives.WriteUInt64LittleEndian(header[24..32], (ulong)source.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(header[32..40], (ulong)encoded.Length);
        // Legacy v1 keeps the wrapper-absolute offset; the standalone HostContext runtime uses v2 frame-relative offsets.
        BinaryPrimitives.WriteUInt64LittleEndian(
            header[40..48],
            hostContextMetadata is null ? payloadOffset : encodedOffsetWithinFrame);
        sourceHash.CopyTo(header[48..80]);
        encodedHash.CopyTo(header[80..112]);
        if (hostContextMetadata is not null)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                header[HostContextAbiVersionOffset..],
                hostContextMetadata.AbiVersion);
            BinaryPrimitives.WriteUInt64LittleEndian(
                header[HostContextRequiredCapabilitiesOffset..],
                (ulong)hostContextMetadata.RequiredCapabilities);
            BinaryPrimitives.WriteUInt32LittleEndian(
                header[HostContextEntryNameSizeOffset..],
                checked((uint)entryNameBytes.Length));
        }

        sourceNameBytes.CopyTo(frame.AsSpan(checked((int)headerSize)));
        entryNameBytes.CopyTo(frame.AsSpan(checked((int)entryNameOffset)));
        encoded.CopyTo(frame.AsSpan(checked((int)encodedOffsetWithinFrame)));

        encoding = new PayloadFrameEncoding(
            frame,
            (ulong)source.Length,
            (ulong)encoded.Length,
            sourceHash,
            encodedHash,
            sourceName,
            compression)
        {
            FrameVersion = hostContextMetadata is null ? FormatVersion : HostContextFormatVersion,
            HostContextMetadata = hostContextMetadata,
        };
        diagnostics = Array.Empty<Diagnostic>();
        return true;
    }

    public static PayloadFrameDecodeResult Decode(
        ReadOnlySpan<byte> frame,
        ulong frameOffset,
        PayloadFrameLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        var diagnostics = new DiagnosticBag();
        if (frame.Length < HeaderSize)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame header is truncated.");
            return Failure(diagnostics);
        }

        var commonHeader = frame[..HeaderSize];
        if (!commonHeader[..HeaderMagic.Length].SequenceEqual(HeaderMagic))
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame magic is invalid.");
            return Failure(diagnostics);
        }

        var version = BinaryPrimitives.ReadUInt16LittleEndian(commonHeader[8..10]);
        var expectedHeaderSize = version switch
        {
            FormatVersion => HeaderSize,
            HostContextFormatVersion => HostContextHeaderSize,
            _ => (ushort)0,
        };
        if (expectedHeaderSize == 0)
        {
            diagnostics.Error(DiagnosticCode.PayloadUnsupported, $"Payload frame version {version} is unsupported.");
            return Failure(diagnostics, frameVersion: version);
        }

        var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(commonHeader[10..12]);
        if (headerSize != expectedHeaderSize || frame.Length < expectedHeaderSize)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame header size is invalid.");
            return Failure(diagnostics, frameVersion: version);
        }

        var header = frame[..headerSize];
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(header[12..16]);
        if (flags != DeflateFlag)
        {
            diagnostics.Error(DiagnosticCode.PayloadUnsupported, $"Payload frame flags 0x{flags:X} are unsupported.");
            return Failure(diagnostics, frameVersion: version);
        }

        var sourceArch = BinaryPrimitives.ReadUInt16LittleEndian(header[16..18]);
        var sourceType = BinaryPrimitives.ReadUInt16LittleEndian(header[18..20]);
        if (sourceArch != Elf.ElfConstants.MachineAarch64 || sourceType != Elf.ElfConstants.TypeDyn)
        {
            diagnostics.Error(
                DiagnosticCode.PayloadUnsupported,
                "The payload does not identify a supported AArch64 ET_DYN source.");
            return Failure(diagnostics, frameVersion: version);
        }

        HostContextFrameMetadata? hostContextMetadata = null;
        uint entryNameSize = 0;
        HostContextCapability requiredCapabilities = HostContextCapability.None;
        if (version == HostContextFormatVersion)
        {
            var abiVersion = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextAbiVersionOffset..]);
            var reservedBeforeCapabilities = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextReservedBeforeCapabilitiesOffset..]);
            requiredCapabilities = (HostContextCapability)BinaryPrimitives.ReadUInt64LittleEndian(
                header[HostContextRequiredCapabilitiesOffset..]);
            entryNameSize = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextEntryNameSizeOffset..]);
            var reservedAfterEntryNameSize = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextReservedAfterEntryNameSizeOffset..]);
            if (reservedBeforeCapabilities != 0 || reservedAfterEntryNameSize != 0)
            {
                diagnostics.Error(DiagnosticCode.PayloadMalformed, "The HostContext frame reserved fields are not zero.");
                return Failure(diagnostics, frameVersion: version);
            }

            if (!HostContextContract.IsSupportedVersion(abiVersion)
                || !HostContextContract.HasRequiredCapabilities(
                    requiredCapabilities,
                    HostContextContract.MandatoryCapabilities)
                || !HostContextContract.HasOnlySupportedCapabilities(requiredCapabilities))
            {
                diagnostics.Error(DiagnosticCode.PayloadUnsupported, "The HostContext frame ABI or capabilities are unsupported.");
                return Failure(diagnostics, frameVersion: version);
            }

            if (entryNameSize == 0)
            {
                diagnostics.Error(DiagnosticCode.PayloadMalformed, "The HostContext entry name is empty.");
                return Failure(diagnostics, frameVersion: version);
            }

            if ((ulong)entryNameSize > limits.MaximumEntryNameBytes
                || entryNameSize > HostContextContract.MaximumEntryNameBytes)
            {
                diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The HostContext entry name exceeds the configured limit.");
                return Failure(diagnostics, frameVersion: version);
            }
        }

        var sourceNameSize = BinaryPrimitives.ReadUInt32LittleEndian(header[20..24]);
        if ((ulong)sourceNameSize > limits.MaximumSourceNameBytes)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The source argv[0] name exceeds the configured limit.");
            return Failure(diagnostics, frameVersion: version);
        }

        var sourceSize = BinaryPrimitives.ReadUInt64LittleEndian(header[24..32]);
        var encodedSize = BinaryPrimitives.ReadUInt64LittleEndian(header[32..40]);
        var payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[40..48]);
        if (sourceSize > limits.MaximumSourceBytes
            || encodedSize > limits.MaximumEncodedBytes
            || sourceSize > int.MaxValue
            || encodedSize > int.MaxValue)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The payload exceeds the configured size limits.");
            return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
        }

        if (!TryCheckedAdd((ulong)headerSize, sourceNameSize, out var entryNameOffset)
            || !TryCheckedAdd(entryNameOffset, entryNameSize, out var encodedOffsetWithinFrame)
            || encodedOffsetWithinFrame > (ulong)frame.Length
            || encodedSize != (ulong)frame.Length - encodedOffsetWithinFrame)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame bounds are inconsistent.");
            return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
        }

        var expectedPayloadOffset = encodedOffsetWithinFrame;
        if (version == FormatVersion)
        {
            if (!TryCheckedAdd(frameOffset, encodedOffsetWithinFrame, out expectedPayloadOffset))
            {
                diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame offset overflows its containing wrapper.");
                return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
            }
        }

        if (payloadOffset != expectedPayloadOffset)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame encoded offset is inconsistent.");
            return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
        }

        var sourceNameBytes = frame.Slice((int)headerSize, (int)sourceNameSize);
        string sourceName;
        try
        {
            sourceName = StrictUtf8.GetString(sourceNameBytes);
        }
        catch (DecoderFallbackException)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The source argv[0] name is not valid UTF-8.");
            return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
        }

        if (!IsSafeSourceName(sourceName))
        {
            diagnostics.Error(
                DiagnosticCode.PayloadMalformed,
                "The source argv[0] name is empty, unsafe, or contains a path separator.");
            return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
        }

        if (version == HostContextFormatVersion)
        {
            var entryNameBytes = frame.Slice((int)entryNameOffset, (int)entryNameSize);
            string entryName;
            try
            {
                entryName = StrictUtf8.GetString(entryNameBytes);
            }
            catch (DecoderFallbackException)
            {
                diagnostics.Error(DiagnosticCode.PayloadMalformed, "The HostContext entry name is not valid UTF-8.");
                return Failure(diagnostics, sourceSize, encodedSize, frameVersion: version);
            }

            if (!HostContextContract.TryValidateEntryName(entryName, out var entryNameError))
            {
                diagnostics.Error(
                    DiagnosticCode.PayloadMalformed,
                    entryNameError ?? "The HostContext entry name is invalid.");
                return Failure(
                    diagnostics,
                    sourceSize,
                    encodedSize,
                    sourceName: sourceName,
                    frameVersion: version);
            }

            hostContextMetadata = new HostContextFrameMetadata(
                BinaryPrimitives.ReadUInt32LittleEndian(header[HostContextAbiVersionOffset..]),
                requiredCapabilities,
                entryName);
        }

        var encoded = frame.Slice((int)encodedOffsetWithinFrame, (int)encodedSize);
        var expectedEncodedHash = header[80..112];
        var actualEncodedHash = SHA256.HashData(encoded);
        if (!CryptographicOperations.FixedTimeEquals(expectedEncodedHash, actualEncodedHash))
        {
            diagnostics.Error(DiagnosticCode.PayloadIntegrityMismatch, "The compressed payload digest does not match.");
            return Failure(
                diagnostics,
                sourceSize,
                encodedSize,
                actualEncodedHash,
                sourceName: sourceName,
                frameVersion: version,
                hostContextMetadata: hostContextMetadata);
        }

        byte[] source;
        try
        {
            source = Decompress(encoded, sourceSize, limits.MaximumSourceBytes);
        }
        catch (InvalidDataException exception)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, $"The compressed payload is invalid: {exception.Message}");
            return Failure(
                diagnostics,
                sourceSize,
                encodedSize,
                actualEncodedHash,
                sourceName: sourceName,
                frameVersion: version,
                hostContextMetadata: hostContextMetadata);
        }
        catch (IOException exception)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, $"The compressed payload could not be read: {exception.Message}");
            return Failure(
                diagnostics,
                sourceSize,
                encodedSize,
                actualEncodedHash,
                frameVersion: version,
                hostContextMetadata: hostContextMetadata);
        }

        var actualSourceHash = SHA256.HashData(source);
        if (!CryptographicOperations.FixedTimeEquals(header[48..80], actualSourceHash))
        {
            diagnostics.Error(DiagnosticCode.PayloadIntegrityMismatch, "The recovered source digest does not match.");
            return Failure(
                diagnostics,
                sourceSize,
                encodedSize,
                actualEncodedHash,
                actualSourceHash,
                sourceName,
                version,
                hostContextMetadata);
        }

        return new PayloadFrameDecodeResult(
            source,
            sourceSize,
            encodedSize,
            actualSourceHash,
            actualEncodedHash,
            sourceName,
            PayloadCompression.Deflate,
            diagnostics.ToArray())
        {
            FrameVersion = version,
            HostContextMetadata = hostContextMetadata,
        };
    }

    public static WrapperPayloadResult ReadWrapper(
        ReadOnlySpan<byte> wrapper,
        PayloadFrameLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        var diagnostics = new DiagnosticBag();
        if ((ulong)wrapper.Length > limits.MaximumWrapperBytes)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The wrapper exceeds the configured size limit.");
            return new WrapperPayloadResult(null, 0, 0, null, diagnostics.ToArray());
        }

        if (wrapper.Length < TrailerSize)
        {
            diagnostics.Error(DiagnosticCode.WrapperMalformed, "The wrapper does not contain a payload trailer.");
            return new WrapperPayloadResult(null, 0, 0, null, diagnostics.ToArray());
        }

        var trailer = wrapper[^TrailerSize..];
        if (!trailer[..TrailerMagic.Length].SequenceEqual(TrailerMagic))
        {
            diagnostics.Error(DiagnosticCode.WrapperMalformed, "The wrapper payload trailer magic is invalid.");
            return new WrapperPayloadResult(null, 0, 0, null, diagnostics.ToArray());
        }

        var frameOffset = BinaryPrimitives.ReadUInt64LittleEndian(trailer[8..16]);
        var frameLength = BinaryPrimitives.ReadUInt64LittleEndian(trailer[16..24]);
        if (frameOffset > (ulong)wrapper.Length
            || frameLength < HeaderSize
            || !TryCheckedAdd(frameOffset, frameLength, out var frameEnd)
            || !TryCheckedAdd(frameEnd, TrailerSize, out var wrapperEnd)
            || wrapperEnd != (ulong)wrapper.Length)
        {
            diagnostics.Error(DiagnosticCode.WrapperMalformed, "The wrapper payload trailer bounds are invalid.");
            return new WrapperPayloadResult(null, frameOffset, frameLength, null, diagnostics.ToArray());
        }

        var frame = wrapper.Slice(checked((int)frameOffset), checked((int)frameLength));
        var decoded = Decode(frame, frameOffset, limits);
        return new WrapperPayloadResult(
            decoded.SourceBytes,
            frameOffset,
            frameLength,
            decoded,
            decoded.Diagnostics);
    }

    public static bool HasWrapperTrailer(ReadOnlySpan<byte> wrapper)
    {
        return wrapper.Length >= TrailerSize
            && wrapper[^TrailerSize..][..TrailerMagic.Length].SequenceEqual(TrailerMagic);
    }

    public static bool HasFrameHeader(ReadOnlySpan<byte> wrapper)
    {
        var searchOffset = 0;
        while (searchOffset <= wrapper.Length - HeaderMagic.Length)
        {
            var relativeOffset = wrapper[searchOffset..].IndexOf(HeaderMagic);
            if (relativeOffset < 0)
            {
                return false;
            }

            var frameOffset = searchOffset + relativeOffset;
            if (LooksLikeFrameHeader(wrapper[frameOffset..], (ulong)frameOffset))
            {
                return true;
            }

            searchOffset = frameOffset + 1;
        }

        return false;
    }

    public static byte[] CreateTrailer(ulong frameOffset, ulong frameLength)
    {
        var trailer = new byte[TrailerSize];
        Buffer.BlockCopy(TrailerMagic, 0, trailer, 0, TrailerMagic.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(trailer.AsSpan(8, 8), frameOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(trailer.AsSpan(16, 8), frameLength);
        return trailer;
    }

    private static byte[] Decompress(ReadOnlySpan<byte> encoded, ulong expectedSize, ulong maximumSize)
    {
        if (expectedSize > maximumSize || expectedSize > int.MaxValue)
        {
            throw new InvalidDataException("The decompressed payload size is outside the supported range.");
        }

        using var input = new MemoryStream(encoded.ToArray(), writable: false);
        using var deflate = new DeflateStream(input, CompressionMode.Decompress, leaveOpen: false);
        using var output = new MemoryStream(checked((int)expectedSize));
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = deflate.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            if ((ulong)read > expectedSize
                || (ulong)output.Length > expectedSize - (ulong)read)
            {
                throw new InvalidDataException("The decompressed payload exceeds its declared size.");
            }

            output.Write(buffer, 0, read);
        }

        if ((ulong)output.Length != expectedSize)
        {
            throw new InvalidDataException("The decompressed payload size does not match its declaration.");
        }

        return output.ToArray();
    }

    private static PayloadFrameDecodeResult Failure(
        DiagnosticBag diagnostics,
        ulong sourceSize = 0,
        ulong encodedSize = 0,
        byte[]? encodedHash = null,
        byte[]? sourceHash = null,
        string? sourceName = null,
        ushort frameVersion = 0,
        HostContextFrameMetadata? hostContextMetadata = null) =>
        new(null, sourceSize, encodedSize, sourceHash, encodedHash, sourceName, null, diagnostics.ToArray())
        {
            FrameVersion = frameVersion,
            HostContextMetadata = hostContextMetadata,
        };

    private static bool LooksLikeFrameHeader(ReadOnlySpan<byte> frame, ulong frameOffset)
    {
        if (frame.Length < HeaderSize || !frame[..HeaderMagic.Length].SequenceEqual(HeaderMagic))
        {
            return false;
        }

        var version = BinaryPrimitives.ReadUInt16LittleEndian(frame[8..10]);
        var expectedHeaderSize = version switch
        {
            FormatVersion => HeaderSize,
            HostContextFormatVersion => HostContextHeaderSize,
            _ => (ushort)0,
        };
        if (expectedHeaderSize == 0 || frame.Length < expectedHeaderSize)
        {
            return false;
        }

        var header = frame[..expectedHeaderSize];
        if (BinaryPrimitives.ReadUInt16LittleEndian(header[10..12]) != expectedHeaderSize
            || BinaryPrimitives.ReadUInt32LittleEndian(header[12..16]) != DeflateFlag
            || BinaryPrimitives.ReadUInt16LittleEndian(header[16..18]) != Elf.ElfConstants.MachineAarch64
            || BinaryPrimitives.ReadUInt16LittleEndian(header[18..20]) != Elf.ElfConstants.TypeDyn)
        {
            return false;
        }

        uint entryNameSize = 0;
        if (version == HostContextFormatVersion)
        {
            var abiVersion = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextAbiVersionOffset..]);
            var reservedBeforeCapabilities = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextReservedBeforeCapabilitiesOffset..]);
            var requiredCapabilities = (HostContextCapability)BinaryPrimitives.ReadUInt64LittleEndian(
                header[HostContextRequiredCapabilitiesOffset..]);
            entryNameSize = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextEntryNameSizeOffset..]);
            var reservedAfterEntryNameSize = BinaryPrimitives.ReadUInt32LittleEndian(
                header[HostContextReservedAfterEntryNameSizeOffset..]);
            if (reservedBeforeCapabilities != 0
                || reservedAfterEntryNameSize != 0
                || !HostContextContract.IsSupportedVersion(abiVersion)
                || !HostContextContract.HasRequiredCapabilities(
                    requiredCapabilities,
                    HostContextContract.MandatoryCapabilities)
                || !HostContextContract.HasOnlySupportedCapabilities(requiredCapabilities)
                || entryNameSize == 0
                || entryNameSize > HostContextContract.MaximumEntryNameBytes)
            {
                return false;
            }
        }

        var sourceNameSize = BinaryPrimitives.ReadUInt32LittleEndian(header[20..24]);
        var encodedSize = BinaryPrimitives.ReadUInt64LittleEndian(header[32..40]);
        var payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[40..48]);
        if (sourceNameSize > 4096
            || sourceNameSize > int.MaxValue
            || !TryCheckedAdd((ulong)expectedHeaderSize, sourceNameSize, out var entryNameOffset)
            || !TryCheckedAdd(entryNameOffset, entryNameSize, out var encodedOffsetWithinFrame)
            || encodedOffsetWithinFrame > (ulong)frame.Length
            || encodedSize > (ulong)frame.Length - encodedOffsetWithinFrame)
        {
            return false;
        }

        var expectedPayloadOffset = encodedOffsetWithinFrame;
        if (version == FormatVersion
            && !TryCheckedAdd(frameOffset, encodedOffsetWithinFrame, out expectedPayloadOffset))
        {
            return false;
        }

        if (payloadOffset != expectedPayloadOffset)
        {
            return false;
        }

        var sourceNameBytes = frame.Slice((int)expectedHeaderSize, (int)sourceNameSize);
        try
        {
            var sourceName = StrictUtf8.GetString(sourceNameBytes);
            if (!IsSafeSourceName(sourceName))
            {
                return false;
            }

            if (version == HostContextFormatVersion)
            {
                var entryName = StrictUtf8.GetString(
                    frame.Slice((int)entryNameOffset, (int)entryNameSize));
                return HostContextContract.TryValidateEntryName(entryName, out _);
            }

            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool IsSafeSourceName(string sourceName) =>
        !string.IsNullOrWhiteSpace(sourceName)
        && !sourceName.Contains('\0')
        && !sourceName.Contains('/')
        && !sourceName.Contains('\\')
        && sourceName is not "." and not "..";

    private static bool TryCheckedAdd(ulong left, ulong right, out ulong result)
    {
        result = left + right;
        return result >= left;
    }

    private static bool TryEncodeSourceName(
        string sourceName,
        ulong maximumBytes,
        out byte[] encoded)
    {
        encoded = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(sourceName)
            || sourceName is "." or ".."
            || sourceName.Contains('\0')
            || sourceName.Contains('/')
            || sourceName.Contains('\\'))
        {
            return false;
        }

        try
        {
            encoded = StrictUtf8.GetBytes(sourceName);
        }
        catch (EncoderFallbackException)
        {
            return false;
        }

        return (ulong)encoded.Length <= maximumBytes;
    }
}
