using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;
using UrProtect.Core.Application.Validation;

namespace UrProtect.Core.Tests.Application;

public sealed class ValidationWorkflowTests
{
    [Fact]
    public void EmitsByteIdenticalOutput()
    {
        var input = ElfFixture.MinimalPie();

        var result = new ValidationWorkflow().ValidateStructurally(input, emitOutput: true);

        TestAssertions.Success(result.IsSuccess, result.Diagnostics, "byte-identical no-op output");
        Assert.NotNull(result.OutputBytes);
        TestAssertions.ByteIdentity(input, result.OutputBytes!, "byte-identical no-op output");
    }

    [Fact]
    public void StructuralValidationIsDecoderIndependentByDefault()
    {
        var decoder = new AsmStoneAdapter((encoding, address) =>
            Aarch64DecodeResult.BackendUnavailable(encoding, address));

        var result = new ValidationWorkflow(decoder).ValidateStructurally(ElfFixture.MinimalPie());

        TestAssertions.Success(result.IsSuccess, result.Diagnostics, "structural validation");
        Assert.Equal(ValidationAnalysisMode.StructuralOnly, result.AnalysisMode);
        Assert.Null(result.Analysis);
    }

    [Fact]
    public void UnrelatedUnknownExecutableBytesDoNotAffectStructuralValidation()
    {
        var input = ElfFixture.MinimalPie();
        BinaryPrimitives.WriteUInt32LittleEndian(
            input.AsSpan(ElfFixture.EntryInstructionOffset),
            0xFFFFFFFF);
        var decoder = new AsmStoneAdapter((encoding, address) =>
            Aarch64DecodeResult.BackendUnavailable(encoding, address));

        var result = new ValidationWorkflow(decoder).ValidateStructurally(input);

        TestAssertions.Success(result.IsSuccess, result.Diagnostics, "unknown executable bytes");
        Assert.Null(result.Analysis);
        Assert.DoesNotContain(result.Diagnostics, diagnostic =>
            diagnostic.Code is DiagnosticCode.UnknownInstruction or DiagnosticCode.AsmStoneUnavailable);
    }

    [Fact]
    public void ObservationAnalysisIsExplicitAndRetainsDecoderDiagnostics()
    {
        var decoder = new AsmStoneAdapter((encoding, address) => new Aarch64DecodeResult(
            Aarch64DecodeStatus.UnknownEncoding,
            null,
            $"Synthetic unknown instruction 0x{encoding:X8} at 0x{address:X}."));

        var result = new ValidationWorkflow(decoder).ValidateObservationOnly(ElfFixture.MinimalPie());

        TestAssertions.Success(result.IsSuccess, result.Diagnostics, "observation-only analysis");
        Assert.Equal(ValidationAnalysisMode.ObservationOnly, result.AnalysisMode);
        Assert.NotNull(result.Analysis);
        Assert.Contains(result.Analysis!.Candidates, candidate => candidate.VirtualAddress == 0x1200);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.UnknownInstruction);
    }

    [Fact]
    public void ObservationOnlyCopyRetainsItsExplicitModeOnInputFailure()
    {
        var directory = Directory.CreateTempSubdirectory("urprotect-observation-failure-");
        try
        {
            var result = new ValidationWorkflow().ValidateAndCopyObservationOnly(
                Path.Combine(directory.FullName, "missing.elf"),
                Path.Combine(directory.FullName, "copy.elf"));

            Assert.False(result.IsSuccess);
            Assert.Equal(ValidationAnalysisMode.ObservationOnly, result.AnalysisMode);
            Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.InputIoFailure);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void PreservesUnixModeForCopiedArtifact()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        var directory = Directory.CreateTempSubdirectory("urprotect-mode-");
        try
        {
            var inputPath = Path.Combine(directory.FullName, "input.elf");
            var outputPath = Path.Combine(directory.FullName, "output.elf");
            File.WriteAllBytes(inputPath, ElfFixture.MinimalPie());
            var mode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
            File.SetUnixFileMode(inputPath, mode);
            var decoder = new AsmStoneAdapter((encoding, address) =>
                Aarch64DecodeResult.BackendUnavailable(encoding, address));

            var result = new ValidationWorkflow(decoder).ValidateAndCopyStructurally(inputPath, outputPath);

            TestAssertions.Success(result.IsSuccess, result.Diagnostics, "mode-preserving copy");
            Assert.Equal(mode, File.GetUnixFileMode(outputPath));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void DecoderBackendFailureFailsClosed()
    {
        var decoder = new AsmStoneAdapter((encoding, address) =>
            Aarch64DecodeResult.BackendUnavailable(encoding, address));

        var result = new ValidationWorkflow(decoder).ValidateObservationOnly(ElfFixture.MinimalPie());

        Assert.False(result.IsSuccess);
        Assert.Equal(ValidationAnalysisMode.ObservationOnly, result.AnalysisMode);
        Assert.Contains(result.Diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.AsmStoneUnavailable);
    }

    [Fact]
    public void DoesNotWriteAnOutputForInvalidInput()
    {
        var result = new ValidationWorkflow().ValidateStructurally(
            new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' },
            emitOutput: true);

        Assert.False(result.IsSuccess);
        Assert.Null(result.OutputBytes);
    }

    [Fact]
    public void CopiesValidatedInputThroughAnAtomicOutputPath()
    {
        var directory = Directory.CreateTempSubdirectory("urprotect-test-");
        try
        {
            var inputPath = Path.Combine(directory.FullName, "input.elf");
            var outputPath = Path.Combine(directory.FullName, "output.elf");
            var input = ElfFixture.MinimalPie();
            File.WriteAllBytes(inputPath, input);

            var result = new ValidationWorkflow().ValidateAndCopyStructurally(inputPath, outputPath);

            TestAssertions.Success(result.IsSuccess, result.Diagnostics, "atomic copy");
            TestAssertions.ByteIdentity(input, File.ReadAllBytes(outputPath), "atomic copy");
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void CopyPathCanUseTheAlreadyReadInputSnapshot()
    {
        var directory = Directory.CreateTempSubdirectory("urprotect-snapshot-");
        try
        {
            var inputPath = Path.Combine(directory.FullName, "input.elf");
            var outputPath = Path.Combine(directory.FullName, "output.elf");
            var source = ElfFixture.MinimalPie();
            File.WriteAllBytes(inputPath, source);

            var invalidSnapshot = new byte[] { 0x7F, (byte)'E', (byte)'L', (byte)'F' };
            var result = new ValidationWorkflow().ValidateAndCopyStructurally(
                inputPath,
                outputPath,
                inputOverride: invalidSnapshot);

            Assert.False(result.IsSuccess);
            TestAssertions.ContainsDiagnostic(
                result.Diagnostics,
                DiagnosticCode.InputTooSmall,
                "invalid snapshot publication");
            Assert.False(File.Exists(outputPath));
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }
}
