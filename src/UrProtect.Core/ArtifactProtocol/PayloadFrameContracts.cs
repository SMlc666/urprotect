using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.ArtifactProtocol;

public enum PayloadCompression : uint
{
    Deflate = 1,
}

public sealed record PayloadFrameLimits(
    ulong MaximumSourceBytes = PayloadFrameLimits.DefaultMaximumSourceBytes,
    ulong MaximumEncodedBytes = PayloadFrameLimits.DefaultMaximumEncodedBytes,
    ulong MaximumWrapperBytes = PayloadFrameLimits.DefaultMaximumWrapperBytes,
    ulong MaximumSourceNameBytes = PayloadFrameLimits.DefaultMaximumSourceNameBytes,
    ulong MaximumEntryNameBytes = HostContextContract.MaximumEntryNameBytes)
{
    public const ulong DefaultMaximumSourceBytes = 256UL * 1024 * 1024;
    public const ulong DefaultMaximumEncodedBytes = 256UL * 1024 * 1024;
    public const ulong DefaultMaximumWrapperBytes = 512UL * 1024 * 1024;
    public const ulong DefaultMaximumSourceNameBytes = 4096;
}

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

    public PayloadDispatchProfile? Profile { get; init; }
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

    public PayloadDispatchProfile? Profile { get; init; }
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
