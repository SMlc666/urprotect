using UrProtect.Core.Diagnostics;
using UrProtect.Core.ArtifactProtocol;

namespace UrProtect.Core.Application.Protection;

/// <summary>Single owner for bounded protection-request validation and normalization.</summary>
internal static class FunctionProtectionRequestValidator
{
    public static bool TryValidate(
        FunctionProtectionOptions options,
        DiagnosticBag diagnostics,
        out IReadOnlyList<FunctionSelector> selectors,
        out IReadOnlyList<ProtectionPass> passes)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(diagnostics);
        selectors = Array.Empty<FunctionSelector>();
        passes = Array.Empty<ProtectionPass>();

        if (options.Selectors is null || options.Selectors.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "At least one explicit function selector is required for protection.");
            return false;
        }

        if (options.Passes is null || options.Passes.Count == 0)
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "At least one protection pass is required for protection.");
            return false;
        }

        if (options.Selectors.Count > ProtectedImageLimits.MaximumSelectorCount)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "The protection request contains too many function selectors.");
            return false;
        }

        if (options.Passes.Count > 2)
        {
            diagnostics.Error(
                DiagnosticCode.ProtectedImageLimitExceeded,
                "The protection request contains too many protection passes.");
            return false;
        }

        selectors = options.Selectors.ToArray();
        passes = options.Passes.ToArray();
        if (passes.Any(pass => pass is not (
                ProtectionPass.ControlFlowFlattening
                or ProtectionPass.RegisterPermutation)))
        {
            diagnostics.Error(
                DiagnosticCode.InvalidArgument,
                "The protection request contains an unknown pass.");
            return false;
        }

        return true;
    }
}
