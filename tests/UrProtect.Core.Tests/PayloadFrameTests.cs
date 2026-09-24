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

        TestAssertions.Success(encoded, diagnostics, "v1 frame encoding");
        Assert.NotNull(frame);
        var decoded = PayloadFrameCodec.Decode(
            frame!.FrameBytes,
            frameOffset: 1234,
            new PayloadFrameLimits());

        TestAssertions.FrameSuccess(decoded, "v1 frame decoding");
        Assert.Equal(source, decoded.SourceBytes);
        Assert.Equal("fixture", decoded.SourceName);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(source)).ToLowerInvariant(), frame.SourceSha256Hex);
        Assert.Equal(frame.SourceSha256, decoded.SourceSha256);
        Assert.Equal(frame.EncodedSha256, decoded.EncodedSha256);
        Assert.Equal(PayloadFrameCodec.FormatVersion, frame.FrameVersion);
        Assert.Equal(PayloadFrameCodec.FormatVersion, decoded.FrameVersion);
        Assert.Null(decoded.HostContextMetadata);
    }

    [Fact]
    [Trait("Category", "PackFrame")]
    public void RoundTripsCurrentOuterProfileWithFrameRelativeOffset()
    {
        var source = Enumerable.Range(0, 2048).Select(index => (byte)(index % 31)).ToArray();
        Assert.True(PayloadFrameCodec.TryEncodeCurrent(
            source,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "outer-fixture",
            PayloadDispatchProfile.OuterExecveat,
            null,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        Assert.NotNull(frame);
        Assert.Equal(PayloadFrameCodec.CurrentFormatVersion, frame!.FrameVersion);
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, frame.Profile);
        Assert.Equal(
            (ulong)PayloadFrameCodec.CurrentHeaderSize + (ulong)"outer-fixture"u8.Length,
            BinaryPrimitives.ReadUInt64LittleEndian(
                frame.FrameBytes.AsSpan(PayloadFrameCodec.EncodedOffsetOffset, sizeof(ulong))));

        var decoded = PayloadFrameCodec.Decode(frame.FrameBytes, 1234, new PayloadFrameLimits());
        TestAssertions.FrameSuccess(decoded, "current outer frame decoding");
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, decoded.Profile);
        Assert.Null(decoded.HostContextMetadata);
        Assert.Equal(source, decoded.SourceBytes);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RoundTripsCurrentHostContextProfile()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities,
            "urp_entry");
        Assert.True(PayloadFrameCodec.TryEncodeCurrent(
            ElfFixture.MinimalPie(),
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "entry-image",
            PayloadDispatchProfile.HostContextEntry,
            metadata,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        Assert.NotNull(frame);
        Assert.Equal(PayloadDispatchProfile.HostContextEntry, frame!.Profile);
        var decoded = PayloadFrameCodec.Decode(frame.FrameBytes, 0, new PayloadFrameLimits());
        TestAssertions.FrameSuccess(decoded, "current HostContext frame decoding");
        Assert.Equal(PayloadDispatchProfile.HostContextEntry, decoded.Profile);
        Assert.Equal(metadata, decoded.HostContextMetadata);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RoundTripsHostContextFrameWithExplicitEntrySymbol()
    {
        var source = ElfFixture.MinimalPie();
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities,
            "custom_entry");

        Assert.True(PayloadFrameCodec.TryEncodeHostContext(
            source,
            frameOffset: 1234,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            metadata,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        Assert.NotNull(frame);
        Assert.Equal(PayloadFrameCodec.HostContextFormatVersion, frame!.FrameVersion);
        Assert.Equal(
            PayloadFrameCodec.HostContextHeaderSize,
            BinaryPrimitives.ReadUInt16LittleEndian(
                frame.FrameBytes.AsSpan(PayloadFrameCodec.HeaderSizeOffset, sizeof(ushort))));
        Assert.Equal(
            (ulong)PayloadFrameCodec.HostContextHeaderSize
                + (ulong)"fixture"u8.Length
                + (ulong)"custom_entry"u8.Length,
            BinaryPrimitives.ReadUInt64LittleEndian(
                frame.FrameBytes.AsSpan(PayloadFrameCodec.EncodedOffsetOffset, sizeof(ulong))));

        var decoded = PayloadFrameCodec.Decode(
            frame.FrameBytes,
            frameOffset: 1234,
            new PayloadFrameLimits());

        TestAssertions.FrameSuccess(decoded, "HostContext frame decoding");
        Assert.Equal(source, decoded.SourceBytes);
        Assert.Equal(PayloadFrameCodec.HostContextFormatVersion, decoded.FrameVersion);
        Assert.Equal(metadata, decoded.HostContextMetadata);

        var wrapperPrefix = Enumerable.Repeat((byte)0xA5, 64).ToArray();
        var wrapperWithoutTrailer = wrapperPrefix.Concat(frame.FrameBytes).ToArray();
        Assert.True(PayloadFrameCodec.HasFrameHeader(wrapperWithoutTrailer));
        var wrapper = wrapperWithoutTrailer
            .Concat(PayloadFrameCodec.CreateTrailer(
                (ulong)wrapperPrefix.Length,
                (ulong)frame.FrameBytes.Length))
            .ToArray();
        var wrapperResult = PayloadFrameCodec.ReadWrapper(wrapper, new PayloadFrameLimits());
        Assert.True(
            wrapperResult.IsSuccess,
            $"HostContext wrapper decoding: {string.Join(Environment.NewLine, wrapperResult.Diagnostics)}");
        Assert.Equal(source, wrapperResult.SourceBytes);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RejectsHostContextReservedFields()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities,
            "custom_entry");
        Assert.True(PayloadFrameCodec.TryEncodeHostContext(
            ElfFixture.MinimalPie(),
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            metadata,
            out var frame,
            out _));

        var tampered = frame!.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            tampered.AsSpan(PayloadFrameCodec.HostContextReservedBeforeCapabilitiesOffset, 4),
            1);
        var decoded = PayloadFrameCodec.Decode(tampered, 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RejectsHostContextUnsupportedCapabilities()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities,
            "custom_entry");
        Assert.True(PayloadFrameCodec.TryEncodeHostContext(
            ElfFixture.MinimalPie(),
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            metadata,
            out var frame,
            out _));

        var tampered = frame!.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(
            tampered.AsSpan(PayloadFrameCodec.HostContextRequiredCapabilitiesOffset, 8),
            (ulong)HostContextContract.MandatoryCapabilities | (1UL << 63));
        var decoded = PayloadFrameCodec.Decode(tampered, 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadUnsupported);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RejectsHostContextInvalidUtf8EntryName()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities,
            "custom_entry");
        Assert.True(PayloadFrameCodec.TryEncodeHostContext(
            ElfFixture.MinimalPie(),
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            metadata,
            out var frame,
            out _));

        var tampered = frame!.FrameBytes.ToArray();
        tampered[PayloadFrameCodec.HostContextHeaderSize + "fixture"u8.Length] = 0xFF;
        var decoded = PayloadFrameCodec.Decode(tampered, 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
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
    public void RejectsUnknownFrameVersion()
    {
        Assert.True(PayloadFrameCodec.TryEncode(
            ElfFixture.MinimalPie(),
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            out var frame,
            out _));

        var unsupported = frame!.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(
            unsupported.AsSpan(PayloadFrameCodec.VersionOffset, sizeof(ushort)),
            99);
        var decoded = PayloadFrameCodec.Decode(unsupported, 0, new PayloadFrameLimits());

        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadUnsupported);
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
        BinaryPrimitives.WriteUInt16LittleEndian(
            wrongArchitecture.AsSpan(PayloadFrameCodec.ArchitectureOffset, sizeof(ushort)),
            62);
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
    public void RejectsDotDotAsSourceBasename()
    {
        var encoded = PayloadFrameCodec.TryEncode(
            ElfFixture.MinimalPie(),
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "..",
            out _,
            out var diagnostics);

        Assert.False(encoded);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsUnpairedUtf16SourceName()
    {
        var encoded = PayloadFrameCodec.TryEncode(
            ElfFixture.MinimalPie(),
            0,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "bad\uD800",
            out _,
            out var diagnostics);

        Assert.False(encoded);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
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

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void DoesNotTreatAnEmbeddedMagicStringAsAFrameHeader()
    {
        var launcher = Enumerable.Repeat((byte)0xA5, 256).ToArray();
        "URPCK01\0"u8.CopyTo(launcher.AsSpan(32));

        Assert.False(PayloadFrameCodec.HasFrameHeader(launcher));
    }
}
