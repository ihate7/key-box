using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace KeyBox.Vault
{
    /// <summary>
    /// Надёжная запись файла: данные сначала пишутся во временный файл рядом,
    /// сбрасываются на носитель и проверяются чтением, и только потом заменяют
    /// основной файл. Предыдущая версия сохраняется как «.bak».
    /// Если флешку выдернули посреди записи, прежний файл остаётся целым.
    /// </summary>
    internal static class AtomicFile
    {
        private const int MOVEFILE_REPLACE_EXISTING = 0x1;
        private const int MOVEFILE_WRITE_THROUGH = 0x8;

        /// <summary>
        /// Не использовать замену одной операцией, а сразу идти запасным путём (копия + переименование).
        /// Нужен тестам: так проверяется ветка для файловых систем, где замена одной операцией недоступна.
        /// </summary>
        internal static bool UseSimpleReplace { get; set; }

        public static string BackupPath(string path)
        {
            return path + ".bak";
        }

        public static string TempPath(string path)
        {
            return path + ".tmp";
        }

        public static void Write(string path, byte[] content)
        {
            string temp = TempPath(path);
            string backup = BackupPath(path);

            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(content, 0, content.Length);
                stream.Flush(true);
            }

            byte[] written = File.ReadAllBytes(temp);
            if (!SameBytes(written, content))
            {
                TryDelete(temp);
                throw new IOException("Записанные данные не совпали с исходными. Возможно, носитель неисправен.");
            }

            if (File.Exists(path))
            {
                if (!UseSimpleReplace)
                {
                    try
                    {
                        // Одной операцией: текущий файл → .bak, временный → на его место.
                        File.Replace(temp, path, backup, true);
                        return;
                    }
                    catch (IOException) { }
                    catch (UnauthorizedAccessException) { }
                    catch (PlatformNotSupportedException) { }
                }

                // Запасной путь для файловых систем, где такая замена недоступна:
                // сначала копия текущего файла, затем переименование поверх него.
                if (File.Exists(path))
                {
                    File.Copy(path, backup, true);
                }
            }

            if (!MoveFileEx(temp, path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                int error = Marshal.GetLastWin32Error();
                TryDelete(temp);
                throw new IOException(new Win32Exception(error).Message);
            }
        }

        public static void TryDelete(string path)
        {
            try
            {
                if (File.Exists(path)) File.Delete(path);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
    }
}
