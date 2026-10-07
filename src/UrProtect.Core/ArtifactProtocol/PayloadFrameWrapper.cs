using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.ArtifactProtocol;

public static partial class PayloadFrameCodec
{
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

        var frameOffset = BinaryPrimitives.ReadUInt64LittleEndian(trailer[TrailerFrameOffset..TrailerLengthOffset]);
        var frameLength = BinaryPrimitives.ReadUInt64LittleEndian(trailer[TrailerLengthOffset..TrailerSize]);
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
        var decoded = Decode(frame, limits);
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
            if (LooksLikeFrameHeader(wrapper[frameOffset..]))
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
        BinaryPrimitives.WriteUInt64LittleEndian(trailer.AsSpan(TrailerFrameOffset, sizeof(ulong)), frameOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(trailer.AsSpan(TrailerLengthOffset, sizeof(ulong)), frameLength);
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
        HostContextFrameMetadata? hostContextMetadata = null,
        PayloadDispatchProfile? profile = null) =>
        new(null, sourceSize, encodedSize, sourceHash, encodedHash, sourceName, null, diagnostics.ToArray())
        {
            FrameVersion = frameVersion,
            HostContextMetadata = hostContextMetadata,
            Profile = profile,
        };

    private static bool LooksLikeFrameHeader(ReadOnlySpan<byte> frame)
    {
        if (frame.Length < HeaderSize || !frame[..HeaderMagic.Length].SequenceEqual(HeaderMagic))
        {
            return false;
        }

        var version = BinaryPrimitives.ReadUInt16LittleEndian(frame[VersionOffset..HeaderSizeOffset]);
        if (version != FormatVersion || frame.Length < HeaderSize)
        {
            return false;
        }

        var header = frame[..HeaderSize];
        if (BinaryPrimitives.ReadUInt16LittleEndian(header[HeaderSizeOffset..FlagsOffset]) != HeaderSize
            || BinaryPrimitives.ReadUInt32LittleEndian(header[FlagsOffset..ArchitectureOffset]) != DeflateFlag
            || BinaryPrimitives.ReadUInt16LittleEndian(header[ArchitectureOffset..FileTypeOffset]) != ElfConstants.MachineAarch64
            || BinaryPrimitives.ReadUInt16LittleEndian(header[FileTypeOffset..SourceNameSizeOffset]) != ElfConstants.TypeDyn)
        {
            return false;
        }

        uint entryNameSize = 0;
        PayloadDispatchProfile? profile = null;
        {
            var profileValue = BinaryPrimitives.ReadUInt32LittleEndian(header[ProfileOffset..ReservedOffset]);
            if (BinaryPrimitives.ReadUInt32LittleEndian(header[ReservedOffset..]) != 0
                || (profileValue != (uint)PayloadDispatchProfile.OuterExecveat
                    && profileValue != (uint)PayloadDispatchProfile.HostContextEntry))
            {
                return false;
            }

            profile = (PayloadDispatchProfile)profileValue;
            if (profile == PayloadDispatchProfile.OuterExecveat
                && header[HostContextAbiVersionOffset..ProfileOffset].IndexOfAnyExcept((byte)0) >= 0)
            {
                return false;
            }
        }

        if (profile == PayloadDispatchProfile.HostContextEntry)
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

        var sourceNameSize = BinaryPrimitives.ReadUInt32LittleEndian(header[SourceNameSizeOffset..SourceSizeOffset]);
        var encodedSize = BinaryPrimitives.ReadUInt64LittleEndian(header[EncodedSizeOffset..EncodedOffsetOffset]);
        var payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[EncodedOffsetOffset..SourceSha256Offset]);
        if (sourceNameSize > PayloadFrameLimits.DefaultMaximumSourceNameBytes
            || sourceNameSize > int.MaxValue
            || !TryCheckedAdd((ulong)HeaderSize, sourceNameSize, out var entryNameOffset)
            || !TryCheckedAdd(entryNameOffset, entryNameSize, out var encodedOffsetWithinFrame)
            || encodedOffsetWithinFrame > (ulong)frame.Length
            || encodedSize > (ulong)frame.Length - encodedOffsetWithinFrame)
        {
            return false;
        }

        var expectedPayloadOffset = encodedOffsetWithinFrame;
        if (payloadOffset != expectedPayloadOffset)
        {
            return false;
        }

        var sourceNameBytes = frame.Slice(HeaderSize, (int)sourceNameSize);
        try
        {
            var sourceName = StrictUtf8.GetString(sourceNameBytes);
            if (!IsSafeSourceName(sourceName))
            {
                return false;
            }

            if (profile == PayloadDispatchProfile.HostContextEntry)
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
