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
}
