using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Pack;
using UrProtect.Core.Pipeline;

namespace UrProtect.Core.Tests;

public sealed class LargeInputRegressionTests
{
    [Fact]
    [Trait("Category", "LargeInput")]
    public void ParserAndNoOpPipelineHandleADeclaredLargeInput()
    {
        var input = CreateLargeElf(ReadPositiveInt("URPROTECT_LARGE_INPUT_BYTES", 2 * 1024 * 1024, 16 * 1024 * 1024));
        var parsed = ElfParser.Parse(input);
        Assert.NotNull(parsed.File);
        Assert.DoesNotContain(parsed.Diagnostics, diagnostic => diagnostic.IsError);

        var result = new NoOpPipeline().Validate(input, emitOutput: true, analyzeInstructions: false);
        TestAssertions.Success(result.IsSuccess, result.Diagnostics, "large no-op validation");
        Assert.NotNull(result.OutputBytes);
        TestAssertions.ByteIdentity(input, result.OutputBytes!, "large no-op validation");
    }

    [Fact]
    [Trait("Category", "LargeInput")]
    public void FrameCodecRoundTripsAtTheConfiguredSourceBoundary()
    {
        var sourceSize = ReadPositiveInt("URPROTECT_LARGE_INPUT_BYTES", 2 * 1024 * 1024, 16 * 1024 * 1024);
        var source = Enumerable.Repeat((byte)0xA5, sourceSize).ToArray();
        var limits = new PayloadFrameLimits(
            MaximumSourceBytes: (ulong)sourceSize,
            MaximumEncodedBytes: 4 * 1024 * 1024,
            MaximumWrapperBytes: 8 * 1024 * 1024);
        var encoded = PayloadFrameCodec.TryEncode(
            source,
            frameOffset: 0,
            PayloadCompression.Deflate,
            limits,
            "large-input",
            out var frame,
            out var diagnostics);

        TestAssertions.Success(encoded, diagnostics, "large frame encoding at exact limit");
        var decoded = PayloadFrameCodec.Decode(frame!.FrameBytes, frameOffset: 0, limits);
        TestAssertions.FrameSuccess(decoded, "large frame decoding at exact limit");
        TestAssertions.ByteIdentity(source, decoded.SourceBytes!, "large frame round trip");
    }

    [Fact]
    [Trait("Category", "LargeInput")]
    public void FrameCodecRejectsOneByteAboveTheSourceBoundaryBeforeCompression()
    {
        var sourceSize = ReadPositiveInt("URPROTECT_LARGE_INPUT_BYTES", 2 * 1024 * 1024, 16 * 1024 * 1024);
        var source = new byte[sourceSize + 1];
        var limits = new PayloadFrameLimits(MaximumSourceBytes: (ulong)sourceSize);
        var encoded = PayloadFrameCodec.TryEncode(
            source,
            frameOffset: 0,
            PayloadCompression.Deflate,
            limits,
            "large-input",
            out var frame,
            out var diagnostics);

        Assert.False(encoded);
        Assert.Null(frame);
        TestAssertions.ContainsDiagnostic(
            diagnostics,
            DiagnosticCode.PayloadLimitExceeded,
            "large frame limit-plus-one rejection");
    }

    private static byte[] CreateLargeElf(int size)
    {
        var minimum = ElfFixture.MinimalPie();
        var input = new byte[size];
        minimum.CopyTo(input, 0);
        input.AsSpan(minimum.Length).Fill(0xA5);
        return input;
    }

    private static int ReadPositiveInt(string name, int fallback, int maximum)
    {
        return int.TryParse(Environment.GetEnvironmentVariable(name), out var value)
            ? Math.Clamp(value, 1, maximum)
            : fallback;
    }
}
