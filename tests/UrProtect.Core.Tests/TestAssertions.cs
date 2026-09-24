using UrProtect.Core.Diagnostics;
using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

internal static class TestAssertions
{
    public static void Success(
        bool actual,
        IReadOnlyList<Diagnostic> diagnostics,
        string context)
    {
        Assert.True(
            actual,
            $"{context}: {FormatDiagnostics(diagnostics)}");
    }

    public static void FrameSuccess(
        PayloadFrameDecodeResult result,
        string context)
    {
        Assert.True(
            result.IsSuccess,
            $"{context}: {FormatDiagnostics(result.Diagnostics)}");
    }

    public static void ContainsDiagnostic(
        IEnumerable<Diagnostic> diagnostics,
        DiagnosticCode expectedCode,
        string context)
    {
        Assert.True(
            diagnostics.Any(diagnostic => diagnostic.Code == expectedCode),
            $"{context}: expected diagnostic {expectedCode}; actual {FormatDiagnostics(diagnostics)}");
    }

    public static void ByteIdentity(
        ReadOnlySpan<byte> expected,
        ReadOnlySpan<byte> actual,
        string context)
    {
        Assert.True(
            expected.SequenceEqual(actual),
            $"{context}: expected {expected.Length} bytes to remain byte-identical; actual {actual.Length} bytes");
    }

    private static string FormatDiagnostics(IEnumerable<Diagnostic> diagnostics) =>
        string.Join(
            Environment.NewLine,
            diagnostics.Select(diagnostic =>
                $"{diagnostic.Severity}:{diagnostic.Code}@{diagnostic.Offset}: {diagnostic.Message}"));
}
