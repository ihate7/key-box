using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace KeyBox.Tests
{
    /// <summary>
    /// Запуск процесса на отдельной невидимой «оконной станции» Windows.
    /// У каждой оконной станции свой буфер обмена, поэтому проверка копирования паролей
    /// идёт там и никогда не затрагивает то, что пользователь скопировал сам.
    /// </summary>
    internal static class IsolatedDesktop
    {
        private const int WINSTA_ALL_ACCESS = 0x37F;
        private const int GENERIC_ALL = 0x10000000;
        private const int CREATE_NO_WINDOW = 0x08000000;
        private const int UOI_NAME = 2;

        /// <summary>Запускает команду и ждёт её завершения. Возвращает код выхода процесса.</summary>
        public static int Run(string commandLine, int timeoutMs)
        {
            IntPtr original = GetProcessWindowStation();
            IntPtr station = CreateWindowStation(null, 0, WINSTA_ALL_ACCESS, IntPtr.Zero);
            if (station == IntPtr.Zero) throw new Win32Exception();

            IntPtr desktop = IntPtr.Zero;
            try
            {
                string stationName = NameOf(station);

                // Рабочий стол создаётся на текущей станции процесса — на время переключаемся.
                if (!SetProcessWindowStation(station)) throw new Win32Exception();
                try
                {
                    desktop = CreateDesktop("Default", IntPtr.Zero, IntPtr.Zero, 0, GENERIC_ALL, IntPtr.Zero);
                    if (desktop == IntPtr.Zero) throw new Win32Exception();
                }
                finally
                {
                    SetProcessWindowStation(original);
                }

                var startup = new STARTUPINFO();
                startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startup.lpDesktop = stationName + "\\Default";

                PROCESS_INFORMATION process;
                if (!CreateProcess(null, new StringBuilder(commandLine), IntPtr.Zero, IntPtr.Zero, false,
                        CREATE_NO_WINDOW, IntPtr.Zero, null, ref startup, out process))
                {
                    throw new Win32Exception();
                }

                try
                {
                    if (WaitForSingleObject(process.hProcess, timeoutMs) != 0)
                    {
                        TerminateProcess(process.hProcess, 3);
                        throw new TimeoutException("the process did not finish in " + timeoutMs + " ms");
                    }
                    int exitCode;
                    if (!GetExitCodeProcess(process.hProcess, out exitCode)) throw new Win32Exception();
                    return exitCode;
                }
                finally
                {
                    CloseHandle(process.hProcess);
                    CloseHandle(process.hThread);
                }
            }
            finally
            {
                if (desktop != IntPtr.Zero) CloseDesktop(desktop);
                CloseWindowStation(station);
            }
        }

        private static string NameOf(IntPtr station)
        {
            var buffer = new StringBuilder(260);
            int needed;
            if (!GetUserObjectInformation(station, UOI_NAME, buffer, buffer.Capacity * 2, out needed))
            {
                throw new Win32Exception();
            }
            return buffer.ToString();
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateWindowStation(string name, int flags, int desiredAccess, IntPtr security);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetProcessWindowStation(IntPtr station);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseWindowStation(IntPtr station);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateDesktop(string desktop, IntPtr device, IntPtr deviceMode, int flags, int desiredAccess, IntPtr security);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseDesktop(IntPtr desktop);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetUserObjectInformation(IntPtr handle, int index, StringBuilder info, int length, out int needed);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcess(string applicationName, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, int creationFlags, IntPtr environment,
            string currentDirectory, ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int WaitForSingleObject(IntPtr handle, int milliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr process, out int exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr process, int exitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
