namespace UrProtect.Core.Pack;

public enum PayloadDispatchProfile : uint
{
    OuterExecveat = 1,
    HostContextEntry = 2,
}

public static class PayloadDispatchProfileExtensions
{
    public static string ToCliValue(this PayloadDispatchProfile profile) => profile switch
    {
        PayloadDispatchProfile.OuterExecveat => "outer-execveat",
        PayloadDispatchProfile.HostContextEntry => "host-context-entry",
        _ => throw new ArgumentOutOfRangeException(nameof(profile), profile, "Unknown payload dispatch profile."),
    };

    public static bool TryParse(string value, out PayloadDispatchProfile profile)
    {
        if (string.Equals(value, "outer-execveat", StringComparison.OrdinalIgnoreCase))
        {
            profile = PayloadDispatchProfile.OuterExecveat;
            return true;
        }

        if (string.Equals(value, "host-context-entry", StringComparison.OrdinalIgnoreCase))
        {
            profile = PayloadDispatchProfile.HostContextEntry;
            return true;
        }

        profile = default;
        return false;
    }
}
