using System.Buffers.Binary;
using System.Text.Json;
using UrProtect.Cli;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.Elf;
using UrProtect.Core.Protect;

namespace UrProtect.Core.Tests;

public sealed class FunctionProtectionTests
{
    private const string VersionedFixturePath = "Fixtures/SymbolVersions/liburp-versioned.so";

    [Fact]
    [Trait("Category", "Protect")]
    public void NameSelectionRejectsAmbiguousStaticAndDynamicIdentities()
    {
        var parse = ElfParser.Parse(ReadVersionedFixture());
        Assert.NotNull(parse.File);

        var result = FunctionSelectorResolver.Resolve(
            parse.File!,
            new[] { FunctionSelector.ByName("urp_api_v1") });

        Assert.False(result.IsSuccess);
        var diagnostic = Assert.Single(result.Diagnostics);
        Assert.Equal(DiagnosticCode.FunctionSelectorAmbiguous, diagnostic.Code);
        Assert.Contains("dynsym[3]", diagnostic.Message, StringComparison.Ordinal);
        Assert.Contains("symtab[23]", diagnostic.Message, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void ExplicitIdentityDisambiguationTransformsOnlyTheSelectedRange()
    {
        var source = WithProgramHeaderSlot(ReadVersionedFixture());
        var parse = ElfParser.Parse(source);
        Assert.NotNull(parse.File);
        var selected = Assert.Single(parse.File!.FunctionSymbols, function =>
            function.Table == ElfSymbolTableKind.Static && function.TableIndex == 23);
        var untouched = Assert.Single(parse.File.FunctionSymbols, function =>
            function.Table == ElfSymbolTableKind.Static && function.TableIndex == 21);

        var result = new FunctionProtectionService().Protect(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.Contains(result.Functions, function =>
            function.Function.Table == ElfSymbolTableKind.Static
            && function.Function.TableIndex == 23
            && function.Transformed);

        Assert.True(parse.File.LoadMap.TryVirtualAddressToFileOffset(untouched.Value, untouched.Size, out var untouchedOffset));
        var output = result.OutputBytes!;
        Assert.Equal(
            source.AsSpan(checked((int)untouchedOffset), checked((int)untouched.Size)).ToArray(),
            output.AsSpan(checked((int)untouchedOffset), checked((int)untouched.Size)).ToArray());
        Assert.True(parse.File.LoadMap.TryVirtualAddressToFileOffset(selected.Value, selected.Size, out var selectedOffset));
        Assert.NotEqual(
            source.AsSpan(checked((int)selectedOffset), checked((int)selected.Size)).ToArray(),
            output.AsSpan(checked((int)selectedOffset), checked((int)selected.Size)).ToArray());
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void CombinedPassesUseTheRequiredFlattenThenPermutationOrder()
    {
        var order = ProtectionPassOrdering.Normalize(new[]
        {
            ProtectionPass.RegisterPermutation,
            ProtectionPass.ControlFlowFlattening,
            ProtectionPass.RegisterPermutation,
        });

        Assert.Equal(
            new[] { ProtectionPass.ControlFlowFlattening, ProtectionPass.RegisterPermutation },
            order);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void FailedSelectedTransformationIsAtomic()
    {
        var source = WithProgramHeaderSlot(ReadVersionedFixture());

        var result = new FunctionProtectionService().Protect(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.RegisterPermutation }));

        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
        Assert.Contains(
            result.Diagnostics,
            diagnostic => diagnostic.Code == DiagnosticCode.FunctionResourceUnavailable);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void OccupiedProgramHeaderTableUsesSharedLayoutPlanner()
    {
        var source = ReadVersionedFixture();

        var result = new FunctionProtectionService().Protect(
            source,
            new FunctionProtectionOptions(
                new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
                new[] { ProtectionPass.ControlFlowFlattening }));

        Assert.True(result.IsSuccess, string.Join(Environment.NewLine, result.Diagnostics));
        Assert.NotNull(result.OutputBytes);
        Assert.NotNull(result.LayoutEvidence);
        Assert.Equal(ElfLayoutStrategy.RelocatedProgramHeaderTable, result.LayoutEvidence!.Strategy);
        var parsed = ElfParser.Parse(result.OutputBytes!);
        Assert.True(parsed.IsSuccess, string.Join(Environment.NewLine, parsed.Diagnostics));
        Assert.True(parsed.File!.Header.ProgramHeaderOffset >= (ulong)source.Length);
        Assert.True(parsed.File.Header.ProgramHeaderCount > ElfParser.Parse(source).File!.Header.ProgramHeaderCount);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void CliProtectPreservesExecutableModeAndPublishesReportAtomically()
    {
        using var directory = new TemporaryDirectory();
        var inputPath = directory.Path("input.elf");
        var outputPath = directory.Path("protected.elf");
        var reportPath = directory.Path("protected.json");
        var source = WithProgramHeaderSlot(ReadVersionedFixture());
        File.WriteAllBytes(inputPath, source);
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(inputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        }

        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        var exitCode = CliApplication.Run(
            new[]
            {
                "protect", inputPath, "--output", outputPath,
                "--function-id", "symtab:23", "--pass", "control-flow-flattening",
                "--json", reportPath,
            },
            stdout,
            stderr);

        Assert.Equal((int)ProductExitCode.Success, exitCode);
        Assert.True(File.Exists(outputPath));
        Assert.True(File.Exists(reportPath));
        if (!OperatingSystem.IsWindows())
        {
            Assert.True((File.GetUnixFileMode(outputPath) & UnixFileMode.UserExecute) != 0);
        }

        using var report = JsonDocument.Parse(File.ReadAllText(reportPath));
        Assert.True(report.RootElement.GetProperty("success").GetBoolean());
        Assert.Equal(
            "table=symtab, index=23",
            report.RootElement.GetProperty("selectors")[0].GetString());
        Assert.True(report.RootElement.GetProperty("output").GetProperty("published").GetBoolean());
        var functionReport = Assert.Single(report.RootElement.GetProperty("functions").EnumerateArray());
        Assert.True(functionReport.GetProperty("resourcePlan").GetProperty("sufficient").GetBoolean());
        Assert.Empty(Directory.GetFiles(directory.RootPath, "*.tmp"));
    }

    private static byte[] ReadVersionedFixture() => File.ReadAllBytes(VersionedFixturePath);

    private static byte[] WithProgramHeaderSlot(byte[] source)
    {
        var result = source.ToArray();
        var noteHeaderOffset = ElfConstants.HeaderSize64 + (3 * ElfConstants.ProgramHeaderSize64);
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(noteHeaderOffset), ElfConstants.PtNull);
        return result;
    }

    private sealed class TemporaryDirectory : IDisposable
    {
        private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("urprotect-protect-");

        public string RootPath => directory.FullName;

        public string Path(string fileName) => System.IO.Path.Combine(directory.FullName, fileName);

        public void Dispose() => directory.Delete(recursive: true);
    }
}
