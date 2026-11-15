using System;
using System.IO;
using System.Security;
using System.Threading;
using System.Windows.Forms;
using KeyBox.UI;
using KeyBox.Vault;

namespace KeyBox
{
    internal static class Program
    {
        public const string AppName = "KeyBox";
        public const string Version = "1.1";

        /// <summary>Имя файла хранилища, который лежит рядом с программой.</summary>
        public const string DefaultVaultFileName = "keybox.vault";

        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += OnThreadException;
            AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

            string vaultPath;
            try
            {
                vaultPath = ResolveVaultPath(args);
            }
            catch (ArgumentException ex) { return BadPath(ex); }
            catch (NotSupportedException ex) { return BadPath(ex); }
            catch (IOException ex) { return BadPath(ex); }
            catch (SecurityException ex) { return BadPath(ex); }

            using (var instance = new SingleInstance(vaultPath))
            {
                if (!instance.IsFirst)
                {
                    instance.ActivateFirst();
                    return 0;
                }
                Application.AddMessageFilter(instance);

                try
                {
                    return Run(vaultPath);
                }
                finally
                {
                    // Скопированный пароль не должен пережить программу.
                    ClipboardGuard.ClearIfOwned();
                }
            }
        }

        /// <summary>
        /// Файл хранилища: по умолчанию лежит в папке программы (это и делает её портативной).
        /// Другой файл можно указать первым аргументом командной строки.
        /// </summary>
        internal static string ResolveVaultPath(string[] args)
        {
            string path = null;
            if (args != null && args.Length > 0 && !string.IsNullOrWhiteSpace(args[0]))
            {
                path = args[0].Trim();
            }
            if (path == null)
            {
                path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, DefaultVaultFileName);
            }

            path = Path.GetFullPath(path);
            if (Directory.Exists(path))
            {
                path = Path.Combine(path, DefaultVaultFileName);
            }
            return path;
        }

        /// <summary>Цикл «вход → работа → блокировка → вход».</summary>
        private static int Run(string vaultPath)
        {
            while (true)
            {
                if (!CheckLostVault(vaultPath)) return 0;

                VaultSession session;
                using (var unlock = new UnlockForm(vaultPath))
                {
                    if (unlock.ShowDialog() != DialogResult.OK) return 0;
                    session = unlock.TakeSession();
                }
                if (session == null) return 0;

                bool locked;
                using (session)
                using (var main = new MainForm(session))
                {
                    Application.Run(main);
                    locked = main.LockRequested;
                }

                // Расшифрованные данные больше не нужны — пусть память освободится сразу.
                GC.Collect();
                GC.WaitForPendingFinalizers();

                if (!locked) return 0;
            }
        }

        /// <summary>
        /// Если основной файл пропал, а резервная копия осталась, нельзя молча создавать
        /// новое хранилище: первые же сохранения затёрли бы копию. Предлагаем восстановить.
        /// Возвращает false, если пользователь решил выйти.
        /// </summary>
        private static bool CheckLostVault(string vaultPath)
        {
            string backup = VaultSession.BackupPath(vaultPath);
            if (File.Exists(vaultPath) || !File.Exists(backup)) return true;

            bool restore = MsgBox.Confirm(null, AppName,
                "Файл хранилища не найден:\n" + Ui.FitPath(vaultPath, Ui.Font, MsgBox.TextWidth) + "\n\n" +
                "Но рядом лежит его резервная копия — предыдущая сохранённая версия. Восстановить хранилище из неё?\n\n" +
                "Если нужно начать с пустого хранилища, выйдите и удалите файл копии «" + Path.GetFileName(backup) + "».",
                "Восстановить", "Выход");
            if (!restore) return false;

            try
            {
                File.Copy(backup, vaultPath, false);
                return true;
            }
            catch (IOException ex)
            {
                MsgBox.Error(null, AppName, "Не удалось восстановить хранилище.\n\n" + ex.Message);
            }
            catch (UnauthorizedAccessException ex)
            {
                MsgBox.Error(null, AppName, "Не удалось восстановить хранилище.\n\n" + ex.Message);
            }
            return false;
        }

        private static int BadPath(Exception ex)
        {
            MsgBox.Error(null, AppName, "Не удалось определить путь к файлу хранилища.\n\n" + ex.Message);
            return 2;
        }

        private static void OnThreadException(object sender, ThreadExceptionEventArgs e)
        {
            ReportFailure(e.Exception);
        }

        private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            ReportFailure(e.ExceptionObject as Exception);
        }

        private static void ReportFailure(Exception ex)
        {
            string details = ex == null ? "Неизвестная ошибка." : ex.GetType().Name + ": " + ex.Message;
            MessageBox.Show(
                "В программе произошла непредвиденная ошибка.\n\n" + details +
                "\n\nЕсли она повторяется, перезапустите программу.",
                AppName, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }
}
