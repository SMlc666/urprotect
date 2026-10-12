using System.Runtime.InteropServices;
using UrProtect.Core.ArtifactProtocol;
using UrProtect.Core.Application.Validation;
using UrProtect.Core.Diagnostics;
using UrProtect.Core.StructuralElf;

namespace UrProtect.Core.Infrastructure.Native;

/// <summary>
/// Linux native handoff adapter for an embedded current payload frame.
/// Core owns frame decoding and structural validation; this adapter owns only
/// process and libc handoff details.
/// </summary>
public static class EmbeddedPayloadLauncher
{
    private const int FileSystemExitCode = 3;
    private const int ValidationExitCode = 4;
    private const int OutputIdentityExitCode = 5;
    private const int UsageExitCode = 2;
    private const int InternalExitCode = 10;
    private const int MaxCommandLineArguments = 4096;
    private const uint MemfdCloexec = 1;
    public static int? Run()
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(Environment.ProcessPath))
        {
            return null;
        }

        byte[] wrapper;
        try
        {
            wrapper = File.ReadAllBytes(Environment.ProcessPath);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"InputIoFailure: could not inspect the launcher executable: {exception.Message}");
            return (int)FileSystemExitCode;
        }

        if (!PayloadFrameCodec.HasWrapperTrailer(wrapper))
        {
            if (PayloadFrameCodec.HasFrameHeader(wrapper))
            {
                Console.Error.WriteLine(
                    "WrapperMalformed: the embedded payload frame trailer is missing or truncated.");
                return (int)ValidationExitCode;
            }

            return null;
        }

        var payload = PayloadFrameCodec.ReadWrapper(wrapper, new PayloadFrameLimits());
        if (!payload.IsSuccess || payload.SourceBytes is null)
        {
            foreach (var diagnostic in payload.Diagnostics)
            {
                Console.Error.WriteLine(diagnostic);
            }

            return payload.Diagnostics.Any(diagnostic => diagnostic.Code == DiagnosticCode.PayloadIntegrityMismatch)
                ? (int)OutputIdentityExitCode
                : (int)ValidationExitCode;
        }

        var validation = new ValidationWorkflow().ValidateStructurally(payload.SourceBytes);
        if (!validation.IsSuccess || validation.File?.Kind != ElfFileKind.PieExecutable)
        {
            foreach (var diagnostic in validation.Diagnostics)
            {
                Console.Error.WriteLine(diagnostic);
            }

            Console.Error.WriteLine(
                "UnsupportedPackInput: the recovered payload is not a valid AArch64 PIE executable.");
            return (int)ValidationExitCode;
        }

        int payloadFd;
        Microsoft.Win32.SafeHandles.SafeFileHandle? payloadHandle = null;
        FileStream? payloadStream = null;
        try
        {
            try
            {
                var payloadName = Marshal.StringToCoTaskMemUTF8("urprotect-payload");
                try
                {
                    payloadFd = MemfdCreate(payloadName, MemfdCloexec);
                }
                finally
                {
                    Marshal.FreeCoTaskMem(payloadName);
                }

                if (payloadFd < 0)
                {
                    Console.Error.WriteLine("OutputIoFailure: could not create an anonymous payload image.");
                    return (int)FileSystemExitCode;
                }

                payloadHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(
                    (IntPtr)payloadFd,
                    ownsHandle: true);
                payloadStream = new FileStream(payloadHandle, FileAccess.Write);
                payloadStream.Write(payload.SourceBytes);
                payloadStream.Flush(flushToDisk: true);
                if (Fchmod(payloadFd, 0x1C0) != 0)
                {
                    Console.Error.WriteLine("OutputIoFailure: could not make the anonymous payload executable.");
                    return (int)FileSystemExitCode;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
            {
                Console.Error.WriteLine($"OutputIoFailure: could not write the anonymous payload image: {exception.Message}");
                return (int)FileSystemExitCode;
            }

            var commandLine = Environment.GetCommandLineArgs();
            if (commandLine.Length == 0 || commandLine.Length > MaxCommandLineArguments)
            {
                Console.Error.WriteLine("InvalidArgument: the command line is outside the supported bounds.");
                return (int)UsageExitCode;
            }

            commandLine[0] = payload.Frame?.SourceName ?? commandLine[0];

            var environment = Environment.GetEnvironmentVariables()
                .Cast<System.Collections.DictionaryEntry>()
                .Select(entry => $"{entry.Key}={entry.Value}")
                .ToArray();
            using var nativeArguments = NativeStringArray.Create(commandLine);
            using var nativeEnvironment = NativeStringArray.Create(environment);
            var emptyPath = Marshal.StringToCoTaskMemUTF8(string.Empty);
            try
            {
                var execResult = Execveat(
                    payloadFd,
                    emptyPath,
                    nativeArguments.Pointer,
                    nativeEnvironment.Pointer,
                    AtEmptyPath);
                if (execResult == 0)
                {
                    Console.Error.WriteLine("InternalFailure: execveat returned success without replacing the process.");
                    return (int)InternalExitCode;
                }

                var error = Marshal.GetLastWin32Error();
                Console.Error.WriteLine($"OutputIoFailure: execveat failed for the anonymous payload image (errno {error}).");
                return (int)FileSystemExitCode;
            }
            finally
            {
                Marshal.FreeCoTaskMem(emptyPath);
            }
        }
        catch (Exception exception) when (
            exception is DllNotFoundException
                or EntryPointNotFoundException
                or BadImageFormatException)
        {
            Console.Error.WriteLine(
                $"OutputIoFailure: the anonymous payload handoff is unavailable: {exception.Message}");
            return (int)FileSystemExitCode;
        }
        finally
        {
            payloadStream?.Dispose();
            payloadHandle?.Dispose();
        }
    }

    private const int AtEmptyPath = 0x1000;

    [DllImport("libc", EntryPoint = "memfd_create", SetLastError = true)]
    private static extern int MemfdCreate(
        IntPtr name,
        uint flags);

    [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int Fchmod(int fileDescriptor, uint mode);

    [DllImport("libc", EntryPoint = "execveat", SetLastError = true)]
    private static extern int Execveat(
        int directoryFileDescriptor,
        IntPtr path,
        IntPtr argv,
        IntPtr environment,
        int flags);

    private sealed class NativeStringArray : IDisposable
    {
        private readonly IntPtr[] strings;

        private NativeStringArray(IntPtr pointer, IntPtr[] strings)
        {
            Pointer = pointer;
            this.strings = strings;
        }

        public IntPtr Pointer { get; }

        public static NativeStringArray Create(IEnumerable<string> values)
        {
            var strings = values.Select(Marshal.StringToCoTaskMemUTF8).ToArray();
            var pointer = Marshal.AllocHGlobal(checked((strings.Length + 1) * IntPtr.Size));
            for (var index = 0; index < strings.Length; index++)
            {
                Marshal.WriteIntPtr(pointer, index * IntPtr.Size, strings[index]);
            }

            Marshal.WriteIntPtr(pointer, strings.Length * IntPtr.Size, IntPtr.Zero);
            return new NativeStringArray(pointer, strings);
        }

        public void Dispose()
        {
            foreach (var value in strings)
            {
                Marshal.FreeCoTaskMem(value);
            }

            Marshal.FreeHGlobal(Pointer);
        }
    }

}
