using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.ArtifactProtocol;

public static partial class PayloadFrameCodec
{
    public const ushort FormatVersion = 3;
    public const ushort LauncherAbiVersion = LauncherContract.AbiVersion;
    public const int VersionOffset = 8;
    public const int HeaderSizeOffset = 10;
    public const int FlagsOffset = 12;
    public const int ArchitectureOffset = 16;
    public const int FileTypeOffset = 18;
    public const int SourceNameSizeOffset = 20;
    public const int SourceSizeOffset = 24;
    public const int EncodedSizeOffset = 32;
    public const int EncodedOffsetOffset = 40;
    public const int SourceSha256Offset = 48;
    public const int EncodedSha256Offset = 80;
    public const ushort HeaderSize = 144;
    public const int HostContextAbiVersionOffset = 112;
    public const int HostContextReservedBeforeCapabilitiesOffset = 116;
    public const int HostContextRequiredCapabilitiesOffset = 120;
    public const int HostContextEntryNameSizeOffset = 128;
    public const int HostContextReservedAfterEntryNameSizeOffset = 132;
    public const int ProfileOffset = 136;
    public const int ReservedOffset = 140;
    public const int TrailerSize = 24;
    public const int TrailerFrameOffset = 8;
    public const int TrailerLengthOffset = 16;
    public const uint DeflateFlag = (uint)PayloadCompression.Deflate;
    public const int Sha256Size = 32;

    private static readonly byte[] HeaderMagic = "URPCK01\0"u8.ToArray();
    private static readonly byte[] TrailerMagic = "URTRAIL1"u8.ToArray();
    private static readonly Encoding StrictUtf8 = new UTF8Encoding(false, true);
}
