using System.Buffers.Binary;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

public sealed class PayloadFrameTests
{
    [Fact]
    [Trait("Category", "PackFrame")]
    public void RoundTripsCurrentOuterProfileWithFrameRelativeOffset()
    {
        var source = Enumerable.Range(0, 2048).Select(index => (byte)(index % 31)).ToArray();
        Assert.True(PayloadFrameCodec.TryEncode(
            source,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "outer-fixture",
            PayloadDispatchProfile.OuterExecveat,
            null,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        Assert.NotNull(frame);
        Assert.Equal(PayloadFrameCodec.FormatVersion, frame!.FrameVersion);
        Assert.Equal(PayloadDispatchProfile.OuterExecveat, frame.Profile);
        Assert.Equal(
            (ulong)PayloadFrameCodec.HeaderSize + (ulong)"outer-fixture"u8.Length,
            BinaryPrimitives.ReadUInt64LittleEndian(
                frame.FrameBytes.AsSpan(PayloadFrameCodec.EncodedOffsetOffset, sizeof(ulong))));

        var decoded = PayloadFrameCodec.Decode(frame.FrameBytes, new PayloadFrameLimits());
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
        Assert.True(PayloadFrameCodec.TryEncode(
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
        Assert.Equal(PayloadFrameCodec.HeaderSize, BinaryPrimitives.ReadUInt16LittleEndian(
            frame.FrameBytes.AsSpan(PayloadFrameCodec.HeaderSizeOffset, sizeof(ushort))));

        var decoded = PayloadFrameCodec.Decode(frame.FrameBytes, new PayloadFrameLimits());
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

        Assert.True(PayloadFrameCodec.TryEncode(
            source,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            PayloadDispatchProfile.HostContextEntry,
            metadata,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        Assert.NotNull(frame);
        Assert.Equal(PayloadFrameCodec.FormatVersion, frame!.FrameVersion);
        Assert.Equal(
            (ulong)PayloadFrameCodec.HeaderSize
                + (ulong)"fixture"u8.Length
                + (ulong)"custom_entry"u8.Length,
            BinaryPrimitives.ReadUInt64LittleEndian(
                frame.FrameBytes.AsSpan(PayloadFrameCodec.EncodedOffsetOffset, sizeof(ulong))));

        var decoded = PayloadFrameCodec.Decode(frame.FrameBytes, new PayloadFrameLimits());
        TestAssertions.FrameSuccess(decoded, "HostContext frame decoding");
        Assert.Equal(source, decoded.SourceBytes);
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
        var frame = EncodeHostContext("custom_entry");
        var tampered = frame.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(
            tampered.AsSpan(PayloadFrameCodec.HostContextReservedBeforeCapabilitiesOffset, 4),
            1);

        var decoded = PayloadFrameCodec.Decode(tampered, new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RejectsHostContextUnsupportedCapabilities()
    {
        var frame = EncodeHostContext("custom_entry");
        var tampered = frame.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt64LittleEndian(
            tampered.AsSpan(PayloadFrameCodec.HostContextRequiredCapabilitiesOffset, 8),
            (ulong)HostContextContract.MandatoryCapabilities | (1UL << 63));

        var decoded = PayloadFrameCodec.Decode(tampered, new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadUnsupported);
    }

    [Fact]
    [Trait("Category", "PackHostContext")]
    public void RejectsHostContextInvalidUtf8EntryName()
    {
        var frame = EncodeHostContext("custom_entry");
        var tampered = frame.FrameBytes.ToArray();
        tampered[PayloadFrameCodec.HeaderSize + "fixture"u8.Length] = 0xFF;

        var decoded = PayloadFrameCodec.Decode(tampered, new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsTamperedEncodedPayload()
    {
        var frame = EncodeOuter(ElfFixture.MinimalPie());
        var tampered = frame.FrameBytes.ToArray();
        tampered[^1] ^= 0x80;

        var decoded = PayloadFrameCodec.Decode(tampered, new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadIntegrityMismatch);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsTruncatedFrame()
    {
        var decoded = PayloadFrameCodec.Decode(new byte[PayloadFrameCodec.HeaderSize - 1], new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsUnknownFrameVersion()
    {
        var frame = EncodeOuter(ElfFixture.MinimalPie());
        var unsupported = frame.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(
            unsupported.AsSpan(PayloadFrameCodec.VersionOffset, sizeof(ushort)),
            99);

        var decoded = PayloadFrameCodec.Decode(unsupported, new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadUnsupported);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsWrongSourceArchitecture()
    {
        var frame = EncodeOuter(ElfFixture.MinimalPie());
        var wrongArchitecture = frame.FrameBytes.ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(
            wrongArchitecture.AsSpan(PayloadFrameCodec.ArchitectureOffset, sizeof(ushort)),
            62);

        var decoded = PayloadFrameCodec.Decode(wrongArchitecture, new PayloadFrameLimits());
        Assert.False(decoded.IsSuccess);
        Assert.Contains(decoded.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadUnsupported);
    }

    [Fact]
    [Trait("Category", "PackMalformed")]
    public void RejectsSourceLimitBeforeCompression()
    {
        var encoded = PayloadFrameCodec.TryEncode(
            new byte[32],
            PayloadCompression.Deflate,
            new PayloadFrameLimits(MaximumSourceBytes: 31),
            "fixture",
            PayloadDispatchProfile.OuterExecveat,
            null,
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
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "..",
            PayloadDispatchProfile.OuterExecveat,
            null,
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
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "bad\uD800",
            PayloadDispatchProfile.OuterExecveat,
            null,
            out _,
            out var diagnostics);

        Assert.False(encoded);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.PayloadMalformed);
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
        var frame = EncodeOuter(source);
        var trailer = PayloadFrameCodec.CreateTrailer((ulong)launcher.Length, (ulong)frame.FrameBytes.Length);
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

    private static PayloadFrameEncoding EncodeOuter(byte[] source)
    {
        Assert.True(PayloadFrameCodec.TryEncode(
            source,
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            PayloadDispatchProfile.OuterExecveat,
            null,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        return frame!;
    }

    private static PayloadFrameEncoding EncodeHostContext(string entryName)
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities,
            entryName);
        Assert.True(PayloadFrameCodec.TryEncode(
            ElfFixture.MinimalPie(),
            PayloadCompression.Deflate,
            new PayloadFrameLimits(),
            "fixture",
            PayloadDispatchProfile.HostContextEntry,
            metadata,
            out var frame,
            out var diagnostics), string.Join(Environment.NewLine, diagnostics));
        return frame!;
    }
}
