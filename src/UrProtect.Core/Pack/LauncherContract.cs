namespace UrProtect.Core.Pack;

public static class LauncherContract
{
    public const ushort AbiVersion = 2;
    public const string Marker = "URPROTECT-AARCH64-LAUNCHER-V3";
    public const string HostContextMarker = "URPROTECT-AARCH64-HOST-CONTEXT-V3";

    public static bool HasMarker(ReadOnlySpan<byte> launcher, PayloadDispatchProfile profile)
    {
        return launcher.IndexOf(profile == PayloadDispatchProfile.OuterExecveat
            ? MarkerBytes
            : HostContextMarkerBytes) >= 0;
    }

    public static bool HasMarker(ReadOnlySpan<byte> launcher) =>
        HasMarker(launcher, PayloadDispatchProfile.OuterExecveat)
        || HasMarker(launcher, PayloadDispatchProfile.HostContextEntry);

    private static ReadOnlySpan<byte> MarkerBytes =>
        "URPROTECT-AARCH64-LAUNCHER-V3"u8;

    private static ReadOnlySpan<byte> HostContextMarkerBytes =>
        "URPROTECT-AARCH64-HOST-CONTEXT-V3"u8;
}
