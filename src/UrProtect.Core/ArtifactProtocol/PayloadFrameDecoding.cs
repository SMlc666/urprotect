using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.ArtifactProtocol;

public static partial class PayloadFrameCodec
{
    public static PayloadFrameDecodeResult Decode(
        ReadOnlySpan<byte> frame,
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

        var version = BinaryPrimitives.ReadUInt16LittleEndian(commonHeader[VersionOffset..HeaderSizeOffset]);
        if (version != FormatVersion)
        {
            diagnostics.Error(DiagnosticCode.PayloadUnsupported, $"Payload frame version {version} is unsupported.");
            return Failure(diagnostics, frameVersion: version);
        }

        var headerSize = BinaryPrimitives.ReadUInt16LittleEndian(commonHeader[HeaderSizeOffset..FlagsOffset]);
        if (headerSize != HeaderSize || frame.Length < HeaderSize)
        {
            diagnostics.Error(DiagnosticCode.PayloadMalformed, "The payload frame header size is invalid.");
            return Failure(diagnostics, frameVersion: version);
        }

        var header = frame[..headerSize];
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(header[FlagsOffset..ArchitectureOffset]);
        if (flags != DeflateFlag)
        {
            diagnostics.Error(DiagnosticCode.PayloadUnsupported, $"Payload frame flags 0x{flags:X} are unsupported.");
            return Failure(diagnostics, frameVersion: version);
        }

        var sourceArch = BinaryPrimitives.ReadUInt16LittleEndian(header[ArchitectureOffset..FileTypeOffset]);
        var sourceType = BinaryPrimitives.ReadUInt16LittleEndian(header[FileTypeOffset..SourceNameSizeOffset]);
        if (sourceArch != ElfConstants.MachineAarch64 || sourceType != ElfConstants.TypeDyn)
        {
            diagnostics.Error(
                DiagnosticCode.PayloadUnsupported,
                "The payload does not identify a supported AArch64 ET_DYN source.");
            return Failure(diagnostics, frameVersion: version);
        }

        PayloadDispatchProfile? profile = null;
        HostContextFrameMetadata? hostContextMetadata = null;
        uint entryNameSize = 0;
        HostContextCapability requiredCapabilities = HostContextCapability.None;
        {
            var profileValue = BinaryPrimitives.ReadUInt32LittleEndian(header[ProfileOffset..ReservedOffset]);
            var reserved = BinaryPrimitives.ReadUInt32LittleEndian(header[ReservedOffset..]);
            if (reserved != 0
                || (profileValue != (uint)PayloadDispatchProfile.OuterExecveat
                    && profileValue != (uint)PayloadDispatchProfile.HostContextEntry))
            {
                diagnostics.Error(DiagnosticCode.PayloadUnsupported, "The current payload frame profile is unsupported.");
                return Failure(diagnostics, frameVersion: version);
            }

            profile = (PayloadDispatchProfile)profileValue;
            if (profile == PayloadDispatchProfile.HostContextEntry)
            {
                entryNameSize = BinaryPrimitives.ReadUInt32LittleEndian(
                    header[HostContextEntryNameSizeOffset..]);
            }
            else if (header[HostContextAbiVersionOffset..ProfileOffset].IndexOfAnyExcept((byte)0) >= 0)
            {
                diagnostics.Error(DiagnosticCode.PayloadMalformed, "The outer profile carries HostContext metadata.");
                return Failure(diagnostics, frameVersion: version, profile: profile);
            }
        }

        if (profile == PayloadDispatchProfile.HostContextEntry)
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
                return Failure(diagnostics, frameVersion: version, profile: profile);
            }

            if (!HostContextContract.IsSupportedVersion(abiVersion)
                || !HostContextContract.HasRequiredCapabilities(
                    requiredCapabilities,
                    HostContextContract.MandatoryCapabilities)
                || !HostContextContract.HasOnlySupportedCapabilities(requiredCapabilities))
            {
                diagnostics.Error(DiagnosticCode.PayloadUnsupported, "The HostContext frame ABI or capabilities are unsupported.");
                return Failure(diagnostics, frameVersion: version, profile: profile);
            }

            if (entryNameSize == 0)
            {
                diagnostics.Error(DiagnosticCode.PayloadMalformed, "The HostContext entry name is empty.");
                return Failure(diagnostics, frameVersion: version, profile: profile);
            }

            if ((ulong)entryNameSize > limits.MaximumEntryNameBytes
                || entryNameSize > HostContextContract.MaximumEntryNameBytes)
            {
                diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The HostContext entry name exceeds the configured limit.");
                return Failure(diagnostics, frameVersion: version, profile: profile);
            }
        }

        var sourceNameSize = BinaryPrimitives.ReadUInt32LittleEndian(header[SourceNameSizeOffset..SourceSizeOffset]);
        if ((ulong)sourceNameSize > limits.MaximumSourceNameBytes)
        {
            diagnostics.Error(DiagnosticCode.PayloadLimitExceeded, "The source argv[0] name exceeds the configured limit.");
            return Failure(diagnostics, frameVersion: version);
        }

        var sourceSize = BinaryPrimitives.ReadUInt64LittleEndian(header[SourceSizeOffset..EncodedSizeOffset]);
        var encodedSize = BinaryPrimitives.ReadUInt64LittleEndian(header[EncodedSizeOffset..EncodedOffsetOffset]);
        var payloadOffset = BinaryPrimitives.ReadUInt64LittleEndian(header[EncodedOffsetOffset..SourceSha256Offset]);
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

        if (profile == PayloadDispatchProfile.HostContextEntry)
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
        var expectedEncodedHash = header[EncodedSha256Offset..HostContextAbiVersionOffset];
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
        if (!CryptographicOperations.FixedTimeEquals(header[SourceSha256Offset..EncodedSha256Offset], actualSourceHash))
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
            FrameVersion = FormatVersion,
            HostContextMetadata = hostContextMetadata,
            Profile = profile,
        };
    }
}
