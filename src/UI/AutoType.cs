using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace KeyBox.UI
{
    internal enum AutoTypeResult
    {
        /// <summary>Всё введено.</summary>
        Done,

        /// <summary>Нет окна, в которое можно вводить.</summary>
        NoTarget,

        /// <summary>Активное окно сменилось или пользователь держал клавиши — ввод остановлен.</summary>
        Interrupted,

        /// <summary>Windows не приняла ввод.</summary>
        Failed
    }

    /// <summary>Один шаг автоввода: строка текста либо служебная клавиша.</summary>
    internal sealed class AutoTypeStep
    {
        /// <summary>Код клавиши (Tab, Enter) или 0, если шаг — текст.</summary>
        public int Key;

        public string Text;
    }

    /// <summary>
    /// Всё, что автоввод делает с системой: узнаёт активное окно, проверяет клавиши, отправляет
    /// нажатия. Вынесено в отдельный класс, чтобы тесты могли подменить его и ничего не набирать
    /// на настоящем рабочем столе.
    /// </summary>
    internal class AutoTypeSystem
    {
        private const int INPUT_KEYBOARD = 1;
        private const int KEYEVENTF_KEYUP = 0x0002;
        private const int KEYEVENTF_UNICODE = 0x0004;

        private static readonly int[] Modifiers = { 0x10, 0x11, 0x12, 0x5B, 0x5C }; // Shift, Ctrl, Alt, Win слева и справа
        private static readonly string[] ShellClasses = { "Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd" };

        /// <summary>Размер структуры INPUT, как её видит Windows: 40 байт в 64-разрядном процессе, 28 — в 32-разрядном.</summary>
        public static int InputSize
        {
            get { return Marshal.SizeOf(typeof(INPUT)); }
        }

        public virtual IntPtr ForegroundWindow()
        {
            return GetForegroundWindow();
        }

        /// <summary>true для окон самой программы и для рабочего стола с панелью задач: вводить в них незачем.</summary>
        public virtual bool IsOwnOrShell(IntPtr window)
        {
            int processId;
            GetWindowThreadProcessId(window, out processId);
            if (processId == Process.GetCurrentProcess().Id) return true;

            var name = new StringBuilder(64);
            GetClassName(window, name, name.Capacity);
            return Array.IndexOf(ShellClasses, name.ToString()) >= 0;
        }

        public virtual string Title(IntPtr window)
        {
            var text = new StringBuilder(256);
            GetWindowText(window, text, text.Capacity);
            return text.ToString();
        }

        /// <summary>true, пока нажата хотя бы одна из клавиш Shift, Ctrl, Alt или Win.</summary>
        public virtual bool ModifiersDown()
        {
            foreach (int key in Modifiers)
            {
                if ((GetAsyncKeyState(key) & 0x8000) != 0) return true;
            }
            return false;
        }

        /// <summary>Набирает текст. Символы отправляются как есть, раскладка клавиатуры значения не имеет.</summary>
        public virtual bool SendText(string text)
        {
            foreach (char c in text)
            {
                var pair = new INPUT[2];
                pair[0].type = INPUT_KEYBOARD;
                pair[0].data.keyboard.wScan = c;
                pair[0].data.keyboard.dwFlags = KEYEVENTF_UNICODE;
                pair[1] = pair[0];
                pair[1].data.keyboard.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
                if (SendInput(pair.Length, pair, InputSize) != pair.Length) return false;
                Thread.Sleep(4);
            }
            return true;
        }

        /// <summary>Нажимает и отпускает служебную клавишу (Tab, Enter).</summary>
        public virtual bool SendKey(int virtualKey)
        {
            var pair = new INPUT[2];
            pair[0].type = INPUT_KEYBOARD;
            pair[0].data.keyboard.wVk = (ushort)virtualKey;
            pair[1] = pair[0];
            pair[1].data.keyboard.dwFlags = KEYEVENTF_KEYUP;
            return SendInput(pair.Length, pair, InputSize) == pair.Length;
        }

        public virtual void Sleep(int milliseconds)
        {
            Thread.Sleep(milliseconds);
        }

        /// <summary>Убирает окно программы с дороги: активным снова становится окно, которое было активно до него.</summary>
        public virtual void Minimize(Form form)
        {
            form.WindowState = FormWindowState.Minimized;
        }

        /// <summary>Возвращает окно программы на экран (когда ввод не состоялся и нужно показать сообщение).</summary>
        public virtual void Restore(Form form, FormWindowState state)
        {
            form.WindowState = state;
            form.Activate();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MOUSEINPUT
        {
            public int dx;
            public int dy;
            public int mouseData;
            public int dwFlags;
            public int time;
            public IntPtr dwExtraInfo;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KEYBDINPUT
        {
            public ushort wVk;
            public ushort wScan;
            public int dwFlags;
            public int time;
            public IntPtr dwExtraInfo;
        }

        // Объединение из Win32: его размер задаёт самая большая часть (сведения о мыши),
        // хотя используется только клавиатурная.
        [StructLayout(LayoutKind.Explicit)]
        private struct InputData
        {
            [FieldOffset(0)]
            public MOUSEINPUT mouse;

            [FieldOffset(0)]
            public KEYBDINPUT keyboard;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct INPUT
        {
            public int type;
            public InputData data;
        }

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int SendInput(int count, [In] INPUT[] inputs, int size);

        [DllImport("user32.dll")]
        private static extern IntPtr GetForegroundWindow();

        [DllImport("user32.dll")]
        private static extern int GetWindowThreadProcessId(IntPtr window, out int processId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr window, StringBuilder name, int capacity);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr window, StringBuilder text, int capacity);

        [DllImport("user32.dll")]
        private static extern short GetAsyncKeyState(int virtualKey);
    }

    /// <summary>
    /// Автоввод: программа сама набирает логин и пароль в чужом окне — в поле сайта или другой
    /// программы. Порядок такой: пользователь щёлкает в нужное поле, переходит в KeyBox и выбирает
    /// запись; KeyBox сворачивается, активным снова становится то окно, и в него уходят нажатия.
    /// Буфер обмена при этом не используется.
    /// </summary>
    internal static class AutoType
    {
        public const int KeyTab = 0x09;
        public const int KeyEnter = 0x0D;

        private const int WaitForWindowMs = 3000;
        private const int WaitForKeysMs = 2000;

        /// <summary>Доступ к системе; тесты подставляют сюда свою замену.</summary>
        internal static AutoTypeSystem Driver = new AutoTypeSystem();

        /// <summary>
        /// Составляет последовательность ввода: логин, Tab, пароль и, если нужно, Enter.
        /// Пустые части пропускаются; если вводить нечего, список пуст.
        /// </summary>
        public static List<AutoTypeStep> Plan(string login, string password, bool pressEnter)
        {
            var steps = new List<AutoTypeStep>();
            bool hasLogin = !string.IsNullOrEmpty(login);
            bool hasPassword = !string.IsNullOrEmpty(password);

            if (hasLogin) steps.Add(TextStep(login));
            if (hasLogin && hasPassword) steps.Add(KeyStep(KeyTab));
            if (hasPassword) steps.Add(TextStep(password));
            if (steps.Count > 0 && pressEnter) steps.Add(KeyStep(KeyEnter));
            return steps;
        }

        /// <summary>
        /// Ждёт, пока активным станет чужое окно, и вводит в него шаги плана. Если по ходу ввода
        /// активное окно сменилось, ввод останавливается: пароль не должен уйти не туда.
        /// </summary>
        /// <param name="steps">Что вводить.</param>
        /// <param name="title">Заголовок окна, в которое шёл ввод.</param>
        public static AutoTypeResult Run(IList<AutoTypeStep> steps, out string title)
        {
            AutoTypeSystem system = Driver;
            title = "";

            // 1. Окно, которое было активно до нас, снова должно стать активным.
            IntPtr target = IntPtr.Zero;
            for (int waited = 0; waited < WaitForWindowMs; waited += 30)
            {
                IntPtr foreground = system.ForegroundWindow();
                if (foreground != IntPtr.Zero && !system.IsOwnOrShell(foreground))
                {
                    target = foreground;
                    break;
                }
                system.Sleep(30);
            }
            if (target == IntPtr.Zero) return AutoTypeResult.NoTarget;
            title = system.Title(target);

            // 2. Сочетание клавиш, которым вызвали автоввод, должно быть отпущено:
            //    иначе буквы превратились бы в «Ctrl+буква».
            for (int waited = 0; system.ModifiersDown(); waited += 30)
            {
                if (waited >= WaitForKeysMs) return AutoTypeResult.Interrupted;
                system.Sleep(30);
            }
            system.Sleep(150); // окну нужно немного времени, чтобы принять фокус

            // 3. Ввод по шагам; перед каждым проверяем, что окно всё то же.
            foreach (AutoTypeStep step in steps)
            {
                if (system.ForegroundWindow() != target) return AutoTypeResult.Interrupted;

                bool sent = step.Key != 0 ? system.SendKey(step.Key) : system.SendText(step.Text);
                if (!sent) return AutoTypeResult.Failed;
                system.Sleep(60);
            }
            return AutoTypeResult.Done;
        }

        private static AutoTypeStep TextStep(string text)
        {
            var step = new AutoTypeStep();
            step.Text = text;
            return step;
        }

        private static AutoTypeStep KeyStep(int key)
        {
            var step = new AutoTypeStep();
            step.Key = key;
            return step;
        }
    }
}
