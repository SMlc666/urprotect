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
    ulong MaximumSourceNameBytes = 4096);

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
    public const ushort LauncherAbiVersion = LauncherContract.AbiVersion;
    public const ushort HeaderSize = 112;
    public const int TrailerSize = 24;
    public const uint DeflateFlag = (uint)PayloadCompression.Deflate;
    public const int Sha256Size = 32;

    private static readonly byte[] HeaderMagic = "URPCK01\0"u8.ToArray();
    private static readonly byte[] TrailerMagic = "URTRAIL1"u8.ToArray();

    public static bool TryEncode(
        ReadOnlySpan<byte> source,
        ulong frameOffset,
        PayloadCompression compression,
        PayloadFrameLimits limits,
        string sourceName,
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

        if (!TryCheckedAdd(frameOffset, HeaderSize, out var nameOffset)
            || !TryCheckedAdd(nameOffset, (ulong)sourceNameBytes.Length, out var payloadOffset)
            || !TryCheckedAdd(payloadOffset, (ulong)encoded.Length, out var frameEnd)
            || !TryCheckedAdd(frameEnd, TrailerSize, out var wrapperSize)
            || wrapperSize > limits.MaximumWrapperBytes)
        {
            errors.Error(
                DiagnosticCode.PayloadLimitExceeded,
                "The wrapper size or payload offset exceeds the configured bounds.");
            diagnostics = errors.ToArray();
            return false;
        }

        var sourceHash = SHA256.HashData(source);
        var encodedHash = SHA256.HashData(encoded);
        var frame = new byte[checked(HeaderSize + sourceNameBytes.Length + encoded.Length)];
        var header = frame.AsSpan(0, HeaderSize);
        HeaderMagic.CopyTo(header);
        BinaryPrimitives.WriteUInt16LittleEndian(header[8..10], FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[10..12], HeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[12..16], (uint)compression);
        BinaryPrimitives.WriteUInt16LittleEndian(header[16..18], Elf.ElfConstants.MachineAarch64);
        BinaryPrimitives.WriteUInt16LittleEndian(header[18..20], Elf.ElfConstants.TypeDyn);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..24], checked((uint)sourceNameBytes.Length));
        BinaryPrimitives.WriteUInt64LittleEndian(header[24..32], (ulong)source.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(header[32..40], (ulong)encoded.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(header[40..48], payloadOffset);
        sourceHash.CopyTo(header[48..80]);
        encodedHash.CopyTo(header[80..112]);
        sourceNameBytes.CopyTo(frame.AsSpan(HeaderSize));
        encoded.CopyTo(frame.AsSpan(checked(HeaderSize + sourceNameBytes.Length)));

        encoding = new PayloadFrameEncoding(
            frame,
            (ulong)source.Length,
            (ulong)encoded.Length,
            sourceHash,
            encodedHash,
            sourceName,
            compression);
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

        var header = frame[..HeaderSize];
        if (!header[..HeaderMagic.Length].SequenceEqual(HeaderMagic))
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame magic is invalid.");
            return Failure(diagnostics);
        }

        var version = BinaryPrimitives.ReadUInt16LittleEndian(header[8..10]);
        if (version != FormatVersion)
        {
            diagnostics.Error(DiagnosticCode.PayloadUnsupported, $"Payload frame version {version} is unsupported.");
            return Failure(diagnostics);
        }

        var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(header[10..12]);
        if (headerSize != HeaderSize)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame header size is invalid.");
            return Failure(diagnostics);
        }

        var flags = BinaryPrimitives.ReadUInt32LittleEndian(header[12..16]);
        if (flags != DeflateFlag)
        {
            diagnostics.Error(DiagnosticCode.PayloadUnsupported, $"Payload frame flags 0x{flags:X} are unsupported.");
            return Failure(diagnostics);
        }

        var sourceArch = BinaryPrimitives.ReadUInt16LittleEndian(header[16..18]);
        var sourceType = BinaryPrimitives.ReadUInt16LittleEndian(header[18..20]);
        if (sourceArch != Elf.ElfConstants.MachineAarch64 || sourceType != Elf.ElfConstants.TypeDyn)
        {
            diagnostics.Error(
                DiagnosticCode.PayloadUnsupported,
                "The payload does not identify a supported AArch64 ET_DYN source.");
            return Failure(diagnostics);
        }

        var sourceNameSize = BinaryPrimitives.ReadUInt32LittleEndian(header[20..24]);
        if ((ulong)sourceNameSize > limits.MaximumSourceNameBytes)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The source argv[0] name exceeds the configured limit.");
            return Failure(diagnostics);
        }

        var sourceSize = BinaryPrimitives.ReadUInt64LittleEndian(header[24..32]);
        var encodedSize = BinaryPrimitives.ReadUInt64LittleEndian(header[32..40]);
        var payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[40..48]);
        if (sourceSize > limits.MaximumSourceBytes || encodedSize > limits.MaximumEncodedBytes)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The payload exceeds the configured size limits.");
            return Failure(diagnostics);
        }

        if (!TryCheckedAdd(frameOffset, HeaderSize, out var expectedNameOffset)
            || !TryCheckedAdd(expectedNameOffset, sourceNameSize, out var expectedPayloadOffset)
            || payloadOffset != expectedPayloadOffset
            || sourceNameSize > (ulong)(frame.Length - HeaderSize)
            || encodedSize != (ulong)frame.Length - HeaderSize - sourceNameSize)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame bounds are inconsistent.");
            return Failure(diagnostics);
        }

        var sourceNameBytes = frame.Slice(HeaderSize, checked((int)sourceNameSize));
        string sourceName;
        try
        {
            sourceName = new UTF8Encoding(false, true).GetString(sourceNameBytes);
        }
        catch (DecoderFallbackException)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The source argv[0] name is not valid UTF-8.");
            return Failure(diagnostics, sourceSize, encodedSize);
        }

        if (string.IsNullOrWhiteSpace(sourceName)
            || sourceName.Contains('\0')
            || sourceName.Contains('/')
            || sourceName.Contains('\\')
            || sourceName is "." or "..")
        {
            diagnostics.Error(
                DiagnosticCode.PayloadMalformed,
                "The source argv[0] name is empty, unsafe, or contains a path separator.");
            return Failure(diagnostics, sourceSize, encodedSize);
        }

        var encoded = frame.Slice(checked(HeaderSize + (int)sourceNameSize));
        var expectedEncodedHash = header[80..112];
        var actualEncodedHash = SHA256.HashData(encoded);
        if (!CryptographicOperations.FixedTimeEquals(expectedEncodedHash, actualEncodedHash))
        {
            diagnostics.Error(DiagnosticCode.PayloadIntegrityMismatch, "The compressed payload digest does not match.");
            return Failure(diagnostics, sourceSize, encodedSize, actualEncodedHash, sourceName: sourceName);
        }

        byte[] source;
        try
        {
            source = Decompress(encoded, sourceSize, limits.MaximumSourceBytes);
        }
        catch (InvalidDataException exception)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, $"The compressed payload is invalid: {exception.Message}");
            return Failure(diagnostics, sourceSize, encodedSize, actualEncodedHash, sourceName: sourceName);
        }
        catch (IOException exception)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, $"The compressed payload could not be read: {exception.Message}");
            return Failure(diagnostics, sourceSize, encodedSize, actualEncodedHash);
        }

        var actualSourceHash = SHA256.HashData(source);
        if (!CryptographicOperations.FixedTimeEquals(header[48..80], actualSourceHash))
        {
            diagnostics.Error(DiagnosticCode.PayloadIntegrityMismatch, "The recovered source digest does not match.");
            return Failure(diagnostics, sourceSize, encodedSize, actualEncodedHash, actualSourceHash, sourceName);
        }

        return new PayloadFrameDecodeResult(
            source,
            sourceSize,
            encodedSize,
            actualSourceHash,
            actualEncodedHash,
            sourceName,
            PayloadCompression.Deflate,
            diagnostics.ToArray());
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
        string? sourceName = null) =>
        new(null, sourceSize, encodedSize, sourceHash, encodedHash, sourceName, null, diagnostics.ToArray());

    private static bool LooksLikeFrameHeader(ReadOnlySpan<byte> frame, ulong frameOffset)
    {
        if (frame.Length < HeaderSize || !frame[..HeaderMagic.Length].SequenceEqual(HeaderMagic))
        {
            return false;
        }

        var header = frame[..HeaderSize];
        if (BinaryPrimitives.ReadUInt16LittleEndian(header[8..10]) != FormatVersion
            || BinaryPrimitives.ReadUInt16LittleEndian(header[10..12]) != HeaderSize
            || BinaryPrimitives.ReadUInt32LittleEndian(header[12..16]) != DeflateFlag
            || BinaryPrimitives.ReadUInt16LittleEndian(header[16..18]) != Elf.ElfConstants.MachineAarch64
            || BinaryPrimitives.ReadUInt16LittleEndian(header[18..20]) != Elf.ElfConstants.TypeDyn)
        {
            return false;
        }

        var sourceNameSize = BinaryPrimitives.ReadUInt32LittleEndian(header[20..24]);
        var encodedSize = BinaryPrimitives.ReadUInt64LittleEndian(header[32..40]);
        var payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[40..48]);
        if (sourceNameSize > 4096
            || payloadOffset != frameOffset + HeaderSize + sourceNameSize
            || sourceNameSize > (ulong)(frame.Length - HeaderSize)
            || encodedSize > (ulong)frame.Length - HeaderSize - sourceNameSize)
        {
            return false;
        }

        var sourceNameBytes = frame.Slice(HeaderSize, checked((int)sourceNameSize));
        try
        {
            var sourceName = new UTF8Encoding(false, true).GetString(sourceNameBytes);
            return !string.IsNullOrWhiteSpace(sourceName)
                && !sourceName.Contains('\0')
                && !sourceName.Contains('/')
                && !sourceName.Contains('\\')
                && sourceName is not "." and not "..";
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }

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
            encoded = new UTF8Encoding(false, true).GetBytes(sourceName);
        }
        catch (EncoderFallbackException)
        {
            return false;
        }

        return (ulong)encoded.Length <= maximumBytes;
    }
}
