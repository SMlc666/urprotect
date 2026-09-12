namespace UrProtect.Core.Pack;

public static class LauncherContract
{
    public const ushort AbiVersion = 1;
    public const string Marker = "URPROTECT-AARCH64-LAUNCHER-V1";

    public static bool HasMarker(ReadOnlySpan<byte> launcher)
    {
        return launcher.IndexOf(MarkerBytes) >= 0;
    }

    private static ReadOnlySpan<byte> MarkerBytes =>
        "URPROTECT-AARCH64-LAUNCHER-V1"u8;
}
