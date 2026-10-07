using System.Buffers.Binary;
using UrProtect.Core.Aarch64Semantics;
using UrProtect.Core.SemanticPlanning;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

using UrProtect.Core.ElfLayout;
using UrProtect.Core.ArtifactProtocol;
namespace UrProtect.Core.Application.Protection;

public enum ProtectionPass
{
    ControlFlowFlattening,
    RegisterPermutation,
}

public static class ProtectionPassOrdering
{
    public static IReadOnlyList<ProtectionPass> Normalize(IReadOnlyList<ProtectionPass> passes)
    {
        ArgumentNullException.ThrowIfNull(passes);
        var normalized = new List<ProtectionPass>(2);
        if (passes.Contains(ProtectionPass.ControlFlowFlattening))
        {
            normalized.Add(ProtectionPass.ControlFlowFlattening);
        }

        if (passes.Contains(ProtectionPass.RegisterPermutation))
        {
            normalized.Add(ProtectionPass.RegisterPermutation);
        }

        return normalized;
    }

    public static string Describe(ProtectionPass pass) => pass switch
    {
        ProtectionPass.ControlFlowFlattening => "control-flow-flattening",
        ProtectionPass.RegisterPermutation => "register-permutation",
        _ => pass.ToString(),
    };
}

public sealed record FunctionProtectionOptions(
    IReadOnlyList<FunctionSelector> Selectors,
    IReadOnlyList<ProtectionPass> Passes);

public sealed record FunctionProtectionFunctionResult(
    ElfFunctionSymbol Function,
    bool Selected,
    bool Transformed,
    IReadOnlyList<ProtectionPass> AppliedPasses,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public Aarch64RegisterResourcePlan? ResourcePlan { get; init; }
}

public sealed record FunctionProtectionResult(
    byte[]? OutputBytes,
    IReadOnlyList<FunctionProtectionFunctionResult> Functions,
    IReadOnlyList<Diagnostic> Diagnostics)
{
    public ElfLayoutEvidence? LayoutEvidence { get; init; }

    public string WorkflowOwner { get; init; } = ProtectionWorkflowIdentity.Owner;

    public string? FirstFailureStage { get; init; }

    public bool IsSuccess => OutputBytes is not null
        && Diagnostics.All(diagnostic => !diagnostic.IsError);
}

public sealed partial class FunctionProtectionService
{
    private const byte StateRegister = 16;
    private static readonly IReadOnlyDictionary<byte, byte> RegisterPermutation =
        new Dictionary<byte, byte> { [9] = 10, [10] = 9 };

    private readonly AsmStoneAdapter decoder;

    public FunctionProtectionService(AsmStoneAdapter? decoder = null)
    {
        this.decoder = decoder ?? new AsmStoneAdapter();
    }

}
