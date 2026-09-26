using UrProtect.Core.Pack;

namespace UrProtect.Core.Tests;

public sealed class HostContextContractTests
{
    [Fact]
    public void AcceptsTheVersionedEntryContract()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextCapability.LoadImage
                | HostContextCapability.LookupSymbol
                | HostContextCapability.ReleaseImage,
            HostContextContract.EntrySymbol);

        Assert.True(metadata.IsValid(out var error), error);
        Assert.True(
            HostContextContract.HasRequiredCapabilities(
                HostContextCapability.LoadImage
                    | HostContextCapability.LookupSymbol
                    | HostContextCapability.ReleaseImage,
                HostContextContract.MandatoryCapabilities));
    }

    [Fact]
    public void AcceptsOptionalThreadLifetimeRequirement()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities | HostContextCapability.ThreadLifetime,
            HostContextContract.EntrySymbol);

        Assert.True(metadata.IsValid(out var error), error);
        Assert.True(HostContextContract.HasOnlySupportedCapabilities(metadata.RequiredCapabilities));
        Assert.Equal(56U, HostContextContract.MinimumContextSize);
        Assert.Equal(72U, HostContextContract.CurrentContextSize);
        Assert.Equal(32U, HostContextContract.MinimumLaunchArgsSize);
        Assert.Equal(40U, HostContextContract.CurrentLaunchArgsSize);
    }

    [Theory]
    [InlineData(0U)]
    [InlineData(2U)]
    public void RejectsUnknownAbiVersions(uint version)
    {
        var metadata = new HostContextFrameMetadata(
            version,
            HostContextCapability.None,
            HostContextContract.EntrySymbol);

        Assert.False(metadata.IsValid(out var error));
        Assert.Contains("unsupported", error, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("")]
    [InlineData("../entry")]
    [InlineData("entry/name")]
    [InlineData("entry\0name")]
    [InlineData("bad\uD800")]
    public void RejectsUnsafeEntryNames(string entryName)
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextCapability.None,
            entryName);

        Assert.False(metadata.IsValid(out var error));
        Assert.NotNull(error);
    }

    [Fact]
    public void RejectsFramesWithoutMandatoryImageLifecycleCapabilities()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextCapability.LoadImage,
            HostContextContract.EntrySymbol);

        Assert.False(metadata.IsValid(out var error));
        Assert.Contains("mandatory", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RejectsUnknownCapabilityBits()
    {
        var metadata = new HostContextFrameMetadata(
            HostContextContract.AbiVersion,
            HostContextContract.MandatoryCapabilities | (HostContextCapability)(1UL << 63),
            HostContextContract.EntrySymbol);

        Assert.False(metadata.IsValid(out var error));
        Assert.Contains("unsupported", error, StringComparison.OrdinalIgnoreCase);
        Assert.False(HostContextContract.HasOnlySupportedCapabilities(metadata.RequiredCapabilities));
    }
}
