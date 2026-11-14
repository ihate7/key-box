using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace KeyBox
{
    /// <summary>
    /// Не даёт открыть одно и то же хранилище в двух копиях программы сразу
    /// (иначе они затирали бы изменения друг друга). Повторный запуск просто
    /// выводит уже открытое окно на передний план.
    /// </summary>
    internal sealed class SingleInstance : IDisposable, IMessageFilter
    {
        private readonly Mutex mutex;
        private readonly int activateMessage;

        public SingleInstance(string vaultPath)
        {
            string id = Identify(vaultPath);
            activateMessage = NativeMethods.RegisterWindowMessage("KeyBox.Activate." + id);

            bool created = true;
            try
            {
                mutex = new Mutex(false, "Local\\KeyBox.Vault." + id, out created);
            }
            catch (UnauthorizedAccessException) { created = true; }
            catch (IOException) { created = true; }
            catch (WaitHandleCannotBeOpenedException) { created = true; }
            IsFirst = created;
        }

        /// <summary>true, если это хранилище ещё никем не открыто.</summary>
        public bool IsFirst { get; private set; }

        /// <summary>Просит уже запущенную копию показать своё окно.</summary>
        public void ActivateFirst()
        {
            if (activateMessage == 0) return;
            NativeMethods.AllowSetForegroundWindow(NativeMethods.ASFW_ANY);
            NativeMethods.PostMessage(NativeMethods.HWND_BROADCAST, activateMessage, IntPtr.Zero, IntPtr.Zero);
        }

        public bool PreFilterMessage(ref Message m)
        {
            if (activateMessage == 0 || m.Msg != activateMessage) return false;

            Form target = null;
            FormCollection forms = Application.OpenForms;
            for (int i = forms.Count - 1; i >= 0; i--)
            {
                if (forms[i].Visible)
                {
                    target = forms[i];
                    break;
                }
            }
            if (target != null)
            {
                Form top = target;
                while (top.Owner != null) top = top.Owner;
                if (top.WindowState == FormWindowState.Minimized)
                {
                    NativeMethods.ShowWindow(top.Handle, NativeMethods.SW_RESTORE);
                }
                target.Activate();
                NativeMethods.SetForegroundWindow(target.Handle);
            }
            return true;
        }

        public void Dispose()
        {
            if (mutex != null) mutex.Dispose();
        }

        private static string Identify(string vaultPath)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(vaultPath.ToUpperInvariant()));
                var builder = new StringBuilder(32);
                for (int i = 0; i < 16; i++)
                {
                    builder.Append(hash[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
