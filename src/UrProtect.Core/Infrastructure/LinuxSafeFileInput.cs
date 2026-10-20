using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using UrProtect.Core.Diagnostics;

namespace UrProtect.Core.Infrastructure;

/// <summary>
/// Linux-only safe open and bounded read helpers for host-supplied provider
/// files. The descriptor is opened nonblocking and without following the final
/// path component, then verified through the fixed Linux statx UAPI before any
/// file bytes are allocated or read.
/// </summary>
internal static class LinuxSafeFileInput
{
    private const int O_RDONLY = 0;
    private const int O_NONBLOCK = 0x800;
    private const int O_CLOEXEC = 0x80000;
    private const int O_NOFOLLOW_X64 = 0x20000;
    private const int O_NOFOLLOW_ARM64 = 0x8000;
    private const int AT_EMPTY_PATH = 0x1000;
    private const uint STATX_TYPE = 0x0001;
    private const uint STATX_SIZE = 0x0200;
    private const ushort S_IFMT = 0xF000;
    private const ushort S_IFREG = 0x8000;
    private const int LinuxStatxSize = 256;

    internal static SafeFileHandle OpenReadOnly(string path)
    {
        // Linux open-flag values are architecture UAPI constants. The product
        // currently targets x86-64 and AArch64 Linux; do not guess on others.
        var noFollowFlag = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => O_NOFOLLOW_X64,
            Architecture.Arm64 => O_NOFOLLOW_ARM64,
            _ => throw new PlatformNotSupportedException("No audited Linux O_NOFOLLOW value is available for this architecture."),
        };
        var utf8Path = Marshal.StringToCoTaskMemUTF8(path);
        int descriptor;
        try
        {
            descriptor = OpenNative(utf8Path, O_RDONLY | O_CLOEXEC | noFollowFlag | O_NONBLOCK);
        }
        finally
        {
            Marshal.FreeCoTaskMem(utf8Path);
        }

        if (descriptor < 0)
        {
            throw new IOException("The bounded input could not be safely opened.");
        }

        return new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
    }

    /// <summary>
    /// Reads from the already-opened descriptor. The optional callback is an
    /// internal deterministic test seam for mutations between the initial
    /// descriptor metadata query and the bounded read.
    /// </summary>
    internal static FileSnapshot ReadFromOpenedHandle(
        SafeFileHandle handle,
        int maximumBytes,
        string fullPath = "",
        Action? afterInitialSizeValidation = null)
    {
        ArgumentNullException.ThrowIfNull(handle);
        var diagnostics = new DiagnosticBag();
        if (maximumBytes < 0)
        {
            diagnostics.Error(DiagnosticCode.InvalidArgument, "The bounded input byte limit is invalid.");
            return Failure();
        }

        if (!TryGetStatx(handle, out var before)
            || (before.Mask & (STATX_TYPE | STATX_SIZE)) != (STATX_TYPE | STATX_SIZE))
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, "The bounded input could not be read.");
            return Failure();
        }

        if ((before.Mode & S_IFMT) != S_IFREG)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, "The bounded input must be a regular file.");
            return Failure();
        }

        if (before.Size > (ulong)maximumBytes)
        {
            diagnostics.Error(
                DiagnosticCode.SemanticPlanSnapshotLimitExceeded,
                "The bounded input exceeds its configured byte limit.");
            return Failure();
        }

        afterInitialSizeValidation?.Invoke();

        var bytes = new byte[checked((int)before.Size)];
        if (!TryReadExactly(handle, bytes, out var changedDuringRead))
        {
            diagnostics.Error(
                DiagnosticCode.InputIoFailure,
                changedDuringRead
                    ? "The bounded input changed size while it was being read."
                    : "The bounded input could not be read.");
            return Failure();
        }

        Span<byte> growthProbe = stackalloc byte[1];
        if (RandomAccess.Read(handle, growthProbe, checked((long)before.Size)) != 0
            || !TryGetStatx(handle, out var after)
            || (after.Mask & (STATX_TYPE | STATX_SIZE)) != (STATX_TYPE | STATX_SIZE)
            || (after.Mode & S_IFMT) != S_IFREG
            || after.Size != before.Size)
        {
            diagnostics.Error(DiagnosticCode.InputIoFailure, "The bounded input changed size while it was being read.");
            return Failure();
        }

        return new FileSnapshot(fullPath, bytes, null, diagnostics.ToArray());

        FileSnapshot Failure() => new(fullPath, Array.Empty<byte>(), null, diagnostics.ToArray());
    }

    private static bool TryReadExactly(SafeFileHandle handle, byte[] bytes, out bool changedDuringRead)
    {
        changedDuringRead = false;
        var bytesRead = 0;
        while (bytesRead < bytes.Length)
        {
            var count = RandomAccess.Read(handle, bytes.AsSpan(bytesRead), bytesRead);
            if (count == 0)
            {
                changedDuringRead = true;
                return false;
            }

            bytesRead += count;
        }

        return true;
    }

    private static bool TryGetStatx(SafeFileHandle handle, out LinuxStatx statx)
    {
        statx = default;
        if (handle.IsInvalid || handle.IsClosed)
        {
            return false;
        }

        var addedReference = false;
        try
        {
            handle.DangerousAddRef(ref addedReference);
            var descriptor = checked((int)handle.DangerousGetHandle().ToInt64());
            var emptyPath = Marshal.StringToCoTaskMemUTF8(string.Empty);
            try
            {
                return StatxNative(
                        descriptor,
                        emptyPath,
                        AT_EMPTY_PATH,
                        STATX_TYPE | STATX_SIZE,
                        out statx)
                    == 0;
            }
            finally
            {
                Marshal.FreeCoTaskMem(emptyPath);
            }
        }
        catch (Exception exception) when (
            exception is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException
                or ObjectDisposedException or InvalidOperationException or OverflowException)
        {
            return false;
        }
        finally
        {
            if (addedReference)
            {
                handle.DangerousRelease();
            }
        }
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenNative(IntPtr path, int flags);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true)]
    private static extern int StatxNative(
        int directoryFileDescriptor,
        IntPtr path,
        int flags,
        uint mask,
        out LinuxStatx statx);

    // Linux UAPI statx layout. Only stx_mask, stx_mode, and stx_size are read;
    // the fixed 256-byte shape avoids libc-specific struct stat layouts.
    [StructLayout(LayoutKind.Sequential, Size = LinuxStatxSize)]
    private struct LinuxStatx
    {
        public uint Mask;
        public uint BlockSize;
        public ulong Attributes;
        public uint LinkCount;
        public uint UserId;
        public uint GroupId;
        public ushort Mode;
        public ushort Spare0;
        public ulong Inode;
        public ulong Size;
    }
}
