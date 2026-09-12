using System.Security.Cryptography;
using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

public sealed class PayloadFrameTests
{
    [Fact]
    [Trait("Category", "PackFrame")]
    public void RoundTripsACompressedSourceWithDigests()
    {
        var source = Enumerable.Range(0, 4096).Select(index => (byte)(index % 17)).ToArray();

        var encoded = PayloadFrameCodec.TryEncode(
            source,
            frameOffset: 1234,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out var frame,
            out var diagnostics);

        Assert.True(encoded, string.Join(Environment.NewLine, diagnostics));
        Assert.NotNull(frame);
        var decoded = PayloadFrameCodec.Decode(
            frame!.FrameBytes,
            frameOffset: 1234,
            new PayloadFrameLimits());

        Assert.True(decoded.IsSuccess, string.Join(Environment.NewLine, decoded.Diagnostics));
        Assert.Equal(source, decoded.SourceBytes);
        Assert.Equal("fixture", decoded.SourceName);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant(), frame.SourceSha256Hex);
        Assert.Equal(frame.SourceSha256, decoded.SourceSha256);
        Assert.Equal(frame.EncodedSha256, decoded.EncodedSha256);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsTamperedEncodedPayload()
    {
        var source = ElfFixture.MinimalPie();
        Assert.True(PayloadFrameCodec.TryEncode(
            source,
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out var frame,
            out _));

        var tampered = frame!.FrameBytes.ToArray();
        tampered[^1] ^= 0x80;
        var decoded = PayloadFrameCodec.Decode(tampered, 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadIntegrityMismatch);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsTruncatedFrame()
    {
        var decoded = PayloadFrameCodec.Decode(new byte[PayloadFrameCodec.HeaderSize - 1], 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsWrongSourceArchitecture()
    {
        var source = ElfFixture.MinimalPie();
        Assert.True(PayloadFrameCodec.TryEncode(
            source,
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out var frame,
            out _));

        var wrongArchitecture = frame!.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(wrongArchitecture.AsSpan(16, 2), 62);
        var decoded = PayloadFrameCodec.Decode(wrongArchitecture, 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadUnsupported);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsSourceLimitBeforeCompression()
    {
        var source = new byte[32];
        var encoded = PayloadFrameCodec.TryEncode(
            source,
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(MaximumSourceBytes: 31),
            "fixture",
            out _,
            out var diagnostics);

        Assert.False(encoded);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadLimitExceeded);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsFrameOffsetOverflowBeforeAllocation()
    {
        var encoded = PayloadFrameCodec.TryEncode(
            ElfFixture.MinimalPie(),
            ulong.MaxValue,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out _,
            out var diagnostics);

        Assert.False(encoded);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadLimitExceeded);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void NeverThrowsForBoundedRandomFrames()
    {
        var random = new Random(0xC0FFEE);
        for (var iteration = 0; iteration < 100; iteration++)
        {
            var candidate = new byte[random.Next(0, 512)];
            random.NextBytes(candidate);
            var exception = Record.Exception(() =>
                PayloadFrameCodec.ReadWrapper(candidate, new PayloadFrameLimits()));
            Assert.Null(exception);
        }
    }

    [Fact]
    [Trait("Category", "PackWrapper")]
    public void ReadsAFramedWrapperAndRecoversTheSource()
    {
        var source = ElfFixture.MinimalPie();
        var launcher = Enumerable.Repeat((byte)0xA5, 64).ToArray();
        Assert.True(PayloadFrameCodec.TryEncode(
            source,
            (ulong)launcher.Length,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out var frame,
            out _));

        var trailer = PayloadFrameCodec.CreateTrailer((ulong)launcher.Length, (ulong)frame!.FrameBytes.Length);
        var wrapper = launcher.Concat(frame.FrameBytes).Concat(trailer).ToArray();
        var result = PayloadFrameCodec.ReadWrapper(wrapper, new PayloadFrameLimits());

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.Equal(source, result.SourceBytes);
        Assert.True(PayloadFrameCodec.HasWrapperTrailer(wrapper));
    }
}
