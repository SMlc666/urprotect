// Deliberate non-production fixture: the architecture checker must reject it.
using UrProtect.Core.Application.Validation;

namespace UrProtect.Core.StructuralElf;

internal sealed class ForbiddenStructuralDependencyFixture
{
    private readonly ValidationWorkflow workflow = new();
}
