namespace UrProtect.Core.ElfLayout;

internal static class ForbiddenAarch64WordWriter
{
    private static uint EncodeBad(byte register, uint immediate) =>
        0x52800000u | ((immediate & 0xFFFF) << 5) | register;
}
