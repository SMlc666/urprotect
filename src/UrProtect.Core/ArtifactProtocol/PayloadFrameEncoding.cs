using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.ArtifactProtocol;

public static partial class PayloadFrameCodec
{
    public static bool TryEncode(
        ReadOnlySpan<byte> source,
        PayloadCompression compression,
        PayloadFrameLimits limits,
        string sourceName,
        PayloadDispatchProfile profile,
        HostContextFrameMetadata? hostContextMetadata,
        out PayloadFrameEncoding? encoding,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(limits);
        return TryEncodeCore(
            source,
            compression,
            limits,
            sourceName,
            profile,
            hostContextMetadata,
            out encoding,
            out diagnostics);
    }

    private static bool TryEncodeCore(
        ReadOnlySpan<byte> source,
        PayloadCompression compression,
        PayloadFrameLimits limits,
        string sourceName,
        PayloadDispatchProfile profile,
        HostContextFrameMetadata? hostContextMetadata,
        out PayloadFrameEncoding? encoding,
        out IReadOnlyList<Diagnostic> diagnostics)
    {
        ArgumentNullException.ThrowIfNull(limits);
        var errors = new DiagnosticBag();
        encoding = null;

        if (profile is not (PayloadDispatchProfile.OuterExecveat or PayloadDispatchProfile.HostContextEntry))
        {
            errors.Error(DiagnosticCode.PayloadUnsupported, "The dispatch profile is unsupported.");
            diagnostics = errors.ToArray();
            return false;
        }

        if (profile == PayloadDispatchProfile.HostContextEntry
            && hostContextMetadata is null)
        {
            errors.Error(DiagnosticCode.PayloadMalformed, "The HostContext profile requires HostContext metadata.");
            diagnostics = errors.ToArray();
            return false;
        }

        if (profile == PayloadDispatchProfile.OuterExecveat
            && hostContextMetadata is not null)
        {
            errors.Error(DiagnosticCode.PayloadMalformed, "The outer profile cannot carry HostContext metadata.");
            diagnostics = errors.ToArray();
            return false;
        }

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

        const int headerSize = HeaderSize;
        if (!TryCheckedAdd((ulong)headerSize, (ulong)sourceNameBytes.Length, out var entryNameOffset)
            || !TryCheckedAdd(entryNameOffset, (ulong)entryNameBytes.Length, out var encodedOffsetWithinFrame)
            || !TryCheckedAdd(encodedOffsetWithinFrame, (ulong)encoded.Length, out var frameLength)
            || !TryCheckedAdd(frameLength, TrailerSize, out var wrapperSize)
            || wrapperSize > limits.MaximumWrapperBytes
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
            header[VersionOffset..HeaderSizeOffset],
            FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header[HeaderSizeOffset..FlagsOffset], headerSize);
        BinaryPrimitives.WriteUInt32LittleEndian(header[FlagsOffset..ArchitectureOffset], (uint)compression);
        BinaryPrimitives.WriteUInt16LittleEndian(header[ArchitectureOffset..FileTypeOffset], ElfConstants.MachineAarch64);
        BinaryPrimitives.WriteUInt16LittleEndian(header[FileTypeOffset..SourceNameSizeOffset], ElfConstants.TypeDyn);
        BinaryPrimitives.WriteUInt32LittleEndian(header[SourceNameSizeOffset..SourceSizeOffset], checked((uint)sourceNameBytes.Length));
        BinaryPrimitives.WriteUInt64LittleEndian(header[SourceSizeOffset..EncodedSizeOffset], (ulong)source.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(header[EncodedSizeOffset..EncodedOffsetOffset], (ulong)encoded.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(
            header[EncodedOffsetOffset..SourceSha256Offset],
            encodedOffsetWithinFrame);
        sourceHash.CopyTo(header[SourceSha256Offset..EncodedSha256Offset]);
        encodedHash.CopyTo(header[EncodedSha256Offset..HostContextAbiVersionOffset]);
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

        BinaryPrimitives.WriteUInt32LittleEndian(
            header[ProfileOffset..ReservedOffset],
            checked((uint)profile));
        BinaryPrimitives.WriteUInt32LittleEndian(header[ReservedOffset..], 0);

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
            FrameVersion = FormatVersion,
            HostContextMetadata = hostContextMetadata,
            Profile = profile,
        };
        diagnostics = Array.Empty<Diagnostic>();
        return true;
    }
}
