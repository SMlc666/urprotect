using UrProtect.Core.Application.Protection;
using UrProtect.Core.Application.Rehydration;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Tests.Application;

public sealed class ProtectionWorkflowTests
{
    [Fact]
    [Trait("Category", "Protect")]
    public void CurrentWorkflowNormalizesPassesAndOwnsTheFinalFacade()
    {
        var options = new FunctionProtectionOptions(
            new[] { FunctionSelector.ByIdentity(ElfSymbolTableKind.Static, 23) },
            new[] { ProtectionPass.RegisterPermutation, ProtectionPass.ControlFlowFlattening });

        Assert.True(ProtectionWorkflow.TryNormalize(options, out var normalized, out var diagnostics));
        Assert.Empty(diagnostics);
        Assert.Equal(
            new[] { ProtectionPass.ControlFlowFlattening, ProtectionPass.RegisterPermutation },
            normalized.Passes);
        Assert.Equal(ProtectionWorkflowIdentity.Owner, ProtectionWorkflow.Owner);
    }

    [Fact]
    [Trait("Category", "Protect")]
    public void DirectFunctionWriterRouteIsDeleted()
    {
        Assert.Null(typeof(FunctionProtectionService).GetMethod("Protect"));
    }

    [Fact]
    [Trait("Category", "Rehydration")]
    public void HostContextPolicyRejectsMissingEntryBeforeLayout()
    {
        var bytes = File.ReadAllBytes("Fixtures/SymbolVersions/liburp-versioned.so");
        var parsed = ElfParser.Parse(bytes);
        Assert.NotNull(parsed.File);
        var diagnostics = new DiagnosticBag();
        var policy = new HostContextEntryMaterializationPolicy();
        var options = new RehydrationOptions(
            new string('a', 64),
            new string('b', 64),
            "unit.host",
            ProtectedImageProfile.HostContextEntry,
            "producer.host",
            new string('c', 64),
            ProtectedImageAbiV1.DefaultRehydratorConsumerId,
            new string('d', 64));

        Assert.False(policy.ValidateSource(parsed.File!, options, diagnostics));
        Assert.Contains(diagnostics, diagnostic => diagnostic.Code == DiagnosticCode.FunctionNotFound);
    }
}
