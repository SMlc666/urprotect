using System.Diagnostics;

namespace UrProtect.Core.Infrastructure;

/// <summary>Point-in-time process resource values used by evidence records.</summary>
public sealed record ResourceSample(long CpuMilliseconds, long WorkingSetBytes);

/// <summary>Typed resource-sampling port consumed by application workflows.</summary>
public interface IResourceSampler
{
    ResourceSample Capture();
}

/// <summary>Process adapter that owns direct resource sampling APIs.</summary>
public sealed class ProcessResourceSampler : IResourceSampler
{
    public ResourceSample Capture()
    {
        using var process = Process.GetCurrentProcess();
        process.Refresh();
        return new ResourceSample(
            Math.Max(0, (long)process.TotalProcessorTime.TotalMilliseconds),
            Math.Max(0, process.WorkingSet64));
    }
}
