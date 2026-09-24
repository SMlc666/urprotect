using System.IO.Pipes;
using System.Runtime.InteropServices;
using SharpFuzz.Common;

namespace SharpFuzz;

public delegate void ReadOnlySpanAction(ReadOnlySpan<byte> data);

public static unsafe class Fuzzer
{
    private const int MapSize = 1 << 16;
    private const int DataSize = 1 << 20;
    private const int BufferSize = MapSize + DataSize;
    private const int OpenReadWrite = 2;
    private const int ProtectionReadWrite = 0x1 | 0x2;
    private const int MapShared = 0x01;
    private static readonly IntPtr MapFailed = new(-1);

    public static class LibFuzzer
    {
        public static void Run(ReadOnlySpanAction action) => Run(action, ignoreExceptions: false);

        public static void RunAndIgnoreExceptions(ReadOnlySpanAction action) =>
            Run(action, ignoreExceptions: true);

        private static void Run(ReadOnlySpanAction action, bool ignoreExceptions)
        {
            ArgumentNullException.ThrowIfNull(action);

            var path = Environment.GetEnvironmentVariable("__LIBFUZZER_SHM_PATH");
            var statusPipe = Environment.GetEnvironmentVariable("__LIBFUZZER_STATUS_PIPE_ID");
            var controlPipe = Environment.GetEnvironmentVariable("__LIBFUZZER_CONTROL_PIPE_ID");
            if (string.IsNullOrWhiteSpace(path)
                || string.IsNullOrWhiteSpace(statusPipe)
                || string.IsNullOrWhiteSpace(controlPipe))
            {
                RunSingleInput(action);
                return;
            }

            var fd = Native.open(path, OpenReadWrite);
            if (fd < 0)
            {
                throw new IOException($"open({path}) failed: {Marshal.GetLastWin32Error()}");
            }

            var mapping = Native.mmap(
                IntPtr.Zero,
                (UIntPtr)BufferSize,
                ProtectionReadWrite,
                MapShared,
                fd,
                IntPtr.Zero);
            _ = Native.close(fd);
            if (mapping == MapFailed)
            {
                throw new IOException($"mmap({path}) failed: {Marshal.GetLastWin32Error()}");
            }

            try
            {
                Trace.SharedMem = (byte*)mapping;
                using var control = new BinaryReader(
                    new AnonymousPipeClientStream(PipeDirection.In, controlPipe));
                using var status = new BinaryWriter(
                    new AnonymousPipeClientStream(PipeDirection.Out, statusPipe));
                status.Write(0);
                status.Flush();

                try
                {
                    while (true)
                    {
                        Trace.PrevLocation = 0;
                        var size = control.ReadInt32();
                        if (size < 0 || size > DataSize)
                        {
                            throw new InvalidDataException($"fuzz input size {size} exceeds {DataSize}");
                        }

                        var result = 0;
                        try
                        {
                            action(new ReadOnlySpan<byte>((byte*)mapping + MapSize, size));
                        }
                        catch (Exception exception)
                        {
                            if (!ignoreExceptions)
                            {
                                Console.Error.WriteLine(exception);
                                result = 1;
                            }
                        }

                        status.Write(result);
                        status.Flush();
                        if (result != 0)
                        {
                            return;
                        }
                    }
                }
                catch (EndOfStreamException)
                {
                    return;
                }
                catch (IOException)
                {
                    return;
                }
            }
            finally
            {
                Trace.SharedMem = null;
                _ = Native.munmap(mapping, (UIntPtr)BufferSize);
            }
        }

        private static void RunSingleInput(ReadOnlySpanAction action)
        {
            var args = Environment.GetCommandLineArgs();
            if (args.Length <= 1)
            {
                throw new ArgumentException("an input path is required outside libFuzzer");
            }

            action(File.ReadAllBytes(args[1]));
        }
    }

    private static class Native
    {
        [DllImport("libc", SetLastError = true)]
        public static extern int open([MarshalAs(UnmanagedType.LPStr)] string path, int flags);

        [DllImport("libc", SetLastError = true)]
        public static extern int close(int fd);

        [DllImport("libc", SetLastError = true)]
        public static extern IntPtr mmap(
            IntPtr address,
            UIntPtr length,
            int protection,
            int flags,
            int fd,
            IntPtr offset);

        [DllImport("libc", SetLastError = true)]
        public static extern int munmap(IntPtr address, UIntPtr length);
    }
}
