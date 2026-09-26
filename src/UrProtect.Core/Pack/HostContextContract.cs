using System.Text;

namespace UrProtect.Core.Pack;

[Flags]
public enum HostContextCapability : ulong
{
    None = 0,
    LoadImage = 1UL << 0,
    LookupSymbol = 1UL << 1,
    EmitDiagnostic = 1UL << 2,
    ReleaseImage = 1UL << 3,
    ThreadLifetime = 1UL << 4,
}

public static class HostContextContract
{
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public const uint AbiVersion = 1;
    public const uint MinimumContextSize = 56;
    public const uint CurrentContextSize = 72;
    public const uint MinimumLaunchArgsSize = 32;
    public const uint CurrentLaunchArgsSize = 40;
    public const uint ThreadLifetimeContextSize = 72;
    public const string EntrySymbol = "urp_entry";
    public const int MaximumEntryNameBytes = 4096;
    public const uint LoadImageImmutable = 1;
    public const HostContextCapability SupportedCapabilities = HostContextCapability.LoadImage
        | HostContextCapability.LookupSymbol
        | HostContextCapability.EmitDiagnostic
        | HostContextCapability.ReleaseImage
        | HostContextCapability.ThreadLifetime;
    public const HostContextCapability MandatoryCapabilities = HostContextCapability.LoadImage
        | HostContextCapability.LookupSymbol
        | HostContextCapability.ReleaseImage;

    public static bool IsSupportedVersion(uint version) => version == AbiVersion;

    public static bool HasRequiredCapabilities(
        HostContextCapability available,
        HostContextCapability required) =>
        (available & required) == required;

    public static bool HasOnlySupportedCapabilities(HostContextCapability capabilities) =>
        (capabilities & ~SupportedCapabilities) == HostContextCapability.None;

    public static bool TryValidateEntryName(string entryName, out string? error)
    {
        error = null;
        if (string.IsNullOrWhiteSpace(entryName)
            || entryName.Contains('\0')
            || entryName.Contains('/')
            || entryName.Contains('\\')
            || entryName is "." or "..")
        {
            error = "The HostContext entry name is empty or contains a path component.";
            return false;
        }

        try
        {
            if (StrictUtf8.GetByteCount(entryName) > MaximumEntryNameBytes)
            {
                error = "The HostContext entry name exceeds its UTF-8 size limit.";
                return false;
            }
        }
        catch (ArgumentException)
        {
            error = "The HostContext entry name is not valid UTF-16.";
            return false;
        }

        return true;
    }
}

public sealed record HostContextFrameMetadata(
    uint AbiVersion,
    HostContextCapability RequiredCapabilities,
    string EntryName)
{
    public bool IsValid(out string? error)
    {
        if (!HostContextContract.IsSupportedVersion(AbiVersion))
        {
            error = $"HostContext ABI version {AbiVersion} is unsupported.";
            return false;
        }

        if (!HostContextContract.HasRequiredCapabilities(
                RequiredCapabilities,
                HostContextContract.MandatoryCapabilities))
        {
            error = "The HostContext frame does not request the mandatory image lifecycle capabilities.";
            return false;
        }

        if (!HostContextContract.HasOnlySupportedCapabilities(RequiredCapabilities))
        {
            error = "The HostContext frame requests unsupported capability bits.";
            return false;
        }

        return HostContextContract.TryValidateEntryName(EntryName, out error);
    }
}
