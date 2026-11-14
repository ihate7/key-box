using System;
using System.Drawing;
using System.Windows.Forms;

namespace KeyBox.UI
{
    /// <summary>Основа всех окон программы: общий шрифт, значок, ручное масштабирование.</summary>
    internal class BaseForm : Form
    {
        public BaseForm()
        {
            // Размеры задаются через Ui.S(), автоматическое масштабирование Windows Forms не нужно.
            AutoScaleMode = AutoScaleMode.None;
            Font = Ui.Font;
            Icon icon = Ui.AppIcon;
            if (icon != null) Icon = icon;
        }

        protected override bool ShowWithoutActivation
        {
            get { return Ui.NoActivate || base.ShowWithoutActivation; }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            if (Ui.TestOrigin.HasValue)
            {
                Location = Ui.TestOrigin.Value;
            }
        }
    }

    /// <summary>
    /// Основа диалогов: белая область с содержимым и серая полоса с кнопками внизу.
    /// Окно само подбирает размер под содержимое, поэтому одинаково выглядит при любом масштабе экрана.
    /// </summary>
    internal class DialogForm : BaseForm
    {
        private readonly FlowLayoutPanel footer;

        /// <summary>Таблица, в которую наследник кладёт свои элементы.</summary>
        protected readonly TableLayoutPanel Body;

        /// <summary>Ширина области содержимого в пикселях (без полей).</summary>
        protected readonly int ContentWidth;

        protected DialogForm(string title, int bodyWidth)
        {
            Text = title;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            ShowIcon = false;
            StartPosition = FormStartPosition.CenterParent;
            BackColor = SystemColors.Window;
            ForeColor = Ui.TextColor;
            AutoSize = true;
            AutoSizeMode = AutoSizeMode.GrowAndShrink;

            var root = new TableLayoutPanel();
            root.AutoSize = true;
            root.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            root.ColumnCount = 1;
            root.RowCount = 2;
            root.Margin = Padding.Empty;
            root.Padding = Padding.Empty;
            root.Location = Point.Empty;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Body = new TableLayoutPanel();
            Body.AutoSize = true;
            Body.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            Body.Dock = DockStyle.Fill;
            Body.Margin = Padding.Empty;
            Body.Padding = new Padding(Ui.S(22), Ui.S(20), Ui.S(22), Ui.S(18));
            Body.BackColor = SystemColors.Window;
            if (bodyWidth > 0)
            {
                Body.MinimumSize = new Size(Ui.S(bodyWidth), 0);
            }
            ContentWidth = Math.Max(0, Ui.S(bodyWidth) - Body.Padding.Horizontal);

            footer = new FlowLayoutPanel();
            footer.FlowDirection = FlowDirection.RightToLeft;
            footer.WrapContents = false;
            footer.AutoSize = true;
            footer.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            footer.Dock = DockStyle.Fill;
            footer.Margin = Padding.Empty;
            footer.Padding = new Padding(Ui.S(14), Ui.S(11), Ui.S(14), Ui.S(11));
            footer.BackColor = SystemColors.Control;

            root.Controls.Add(Body, 0, 0);
            root.Controls.Add(footer, 0, 1);
            Controls.Add(root);
        }

        protected override void OnLoad(EventArgs e)
        {
            // К этому моменту у всех элементов созданы окна и известны окончательные размеры
            // (некоторые стандартные элементы уточняют высоту только при создании окна).
            Body.PerformLayout();
            base.OnLoad(e);
        }

        /// <summary>true, пока диалог выполняет длительную операцию и закрывать его нельзя.</summary>
        public virtual bool IsBusy
        {
            get { return false; }
        }

        /// <summary>
        /// Кнопки внизу: основная слева, «отмена» справа (как принято в Windows).
        /// Enter нажимает основную, Esc — отмену.
        /// </summary>
        protected void SetButtons(Button primary, Button cancel, bool focusCancel)
        {
            primary.TabIndex = 0;
            if (cancel != null)
            {
                cancel.TabIndex = 1;
                footer.Controls.Add(cancel);
            }
            footer.Controls.Add(primary);

            AcceptButton = primary;
            CancelButton = cancel ?? primary;
            ActiveControl = (focusCancel && cancel != null) ? cancel : primary;
        }
    }

    /// <summary>Сообщения и подтверждения в едином стиле с кнопками на русском языке.</summary>
    internal sealed class MsgBox : DialogForm
    {
        /// <summary>Наибольшая ширина текста сообщения в пикселях; длинные пути стоит сокращать под неё.</summary>
        public static int TextWidth
        {
            get { return Ui.S(420); }
        }

        private MsgBox(IWin32Window owner, string title, string text, int glyph, Color color, Icon fallbackIcon,
            string okText, string cancelText, bool focusCancel)
            : base(title, 0)
        {
            Name = "MsgBox";
            Body.ColumnCount = 2;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Body.Padding = new Padding(Ui.S(22), Ui.S(22), Ui.S(26), Ui.S(22));

            var picture = new PictureBox();
            picture.Size = new Size(Ui.S(32), Ui.S(32));
            picture.SizeMode = PictureBoxSizeMode.Zoom;
            picture.Margin = new Padding(0, 0, Ui.S(14), 0);
            Bitmap image = Ui.Glyph(glyph, 32, color);
            picture.Image = image ?? fallbackIcon.ToBitmap();

            var label = new Label();
            label.Name = "lblText";
            label.AutoSize = true;
            label.UseMnemonic = false;
            label.MaximumSize = new Size(TextWidth, 0);
            label.MinimumSize = new Size(Ui.S(200), Ui.S(32));
            label.TextAlign = ContentAlignment.MiddleLeft;
            label.Margin = Padding.Empty;
            label.Text = text;

            Body.Controls.Add(picture, 0, 0);
            Body.Controls.Add(label, 1, 0);

            Button ok = Ui.MakeButton(okText);
            ok.Name = "btnOk";
            ok.DialogResult = DialogResult.OK;

            Button cancel = null;
            if (cancelText != null)
            {
                cancel = Ui.MakeButton(cancelText);
                cancel.Name = "btnCancel";
                cancel.DialogResult = DialogResult.Cancel;
            }
            SetButtons(ok, cancel, focusCancel);

            if (owner == null)
            {
                StartPosition = FormStartPosition.CenterScreen;
                ShowInTaskbar = true;
                ShowIcon = true;
            }
        }

        public static void Info(IWin32Window owner, string title, string text)
        {
            Show(owner, title, text, Ui.GlyphInfo, Ui.Accent, SystemIcons.Information, "OK", null, false);
        }

        public static void Error(IWin32Window owner, string title, string text)
        {
            Show(owner, title, text, Ui.GlyphError, Ui.Danger, SystemIcons.Error, "OK", null, false);
        }

        /// <summary>Обычный вопрос: по Enter выполняется действие.</summary>
        public static bool Confirm(IWin32Window owner, string title, string text, string okText, string cancelText)
        {
            return Show(owner, title, text, Ui.GlyphQuestion, Ui.Accent, SystemIcons.Question, okText, cancelText, false);
        }

        /// <summary>Сообщение о сбое с предложением повторить операцию.</summary>
        public static bool Retry(IWin32Window owner, string title, string text)
        {
            return Show(owner, title, text, Ui.GlyphError, Ui.Danger, SystemIcons.Error, "Повторить", "Отмена", false);
        }

        /// <summary>Вопрос о необратимом действии: по умолчанию выбрана «Отмена».</summary>
        public static bool ConfirmDanger(IWin32Window owner, string title, string text, string okText)
        {
            return Show(owner, title, text, Ui.GlyphWarning, Color.FromArgb(202, 138, 4), SystemIcons.Warning, okText, "Отмена", true);
        }

        private static bool Show(IWin32Window owner, string title, string text, int glyph, Color color, Icon fallbackIcon,
            string okText, string cancelText, bool focusCancel)
        {
            using (var box = new MsgBox(owner, title, text, glyph, color, fallbackIcon, okText, cancelText, focusCancel))
            {
                return box.ShowDialog(owner) == DialogResult.OK;
            }
        }
    }

    /// <summary>Запрос одной строки текста (название группы) с проверкой.</summary>
    internal sealed class InputBox : DialogForm
    {
        private readonly TextBox input;
        private readonly Label error;
        private readonly Func<string, string> validator;

        private InputBox(string title, string prompt, string initial, string okText, int maxLength, Func<string, string> validator)
            : base(title, 400)
        {
            Name = "InputBox";
            this.validator = validator;

            Body.ColumnCount = 1;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            Label label = Ui.MakeLabel(prompt);

            input = new TextBox();
            input.Name = "txtInput";
            input.Text = initial ?? "";
            input.MaxLength = maxLength;
            input.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            input.Margin = new Padding(0, Ui.S(6), 0, 0);
            input.TextChanged += delegate { Ui.ShowError(error, null); };

            error = Ui.MakeErrorLabel(ContentWidth);

            Body.Controls.Add(label, 0, 0);
            Body.Controls.Add(input, 0, 1);
            Body.Controls.Add(error, 0, 2);

            Button ok = Ui.MakeButton(okText);
            ok.Name = "btnOk";
            ok.Click += OnOk;
            Button cancel = Ui.MakeButton("Отмена");
            cancel.Name = "btnCancel";
            cancel.DialogResult = DialogResult.Cancel;
            SetButtons(ok, cancel, false);

            ActiveControl = input;
            input.SelectAll();
        }

        /// <summary>
        /// Показывает запрос. Возвращает введённую строку без пробелов по краям или null при отмене.
        /// validator получает введённый текст и возвращает сообщение об ошибке либо null.
        /// </summary>
        public static string Ask(IWin32Window owner, string title, string prompt, string initial, string okText, int maxLength, Func<string, string> validator)
        {
            using (var box = new InputBox(title, prompt, initial, okText, maxLength, validator))
            {
                return box.ShowDialog(owner) == DialogResult.OK ? box.input.Text.Trim() : null;
            }
        }

        private void OnOk(object sender, EventArgs e)
        {
            string message = validator == null ? null : validator(input.Text);
            if (message != null)
            {
                Ui.ShowError(error, message);
                input.Focus();
                input.SelectAll();
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }

    /// <summary>Требования к мастер-паролю и подсказка о его длине.</summary>
    internal static class MasterPasswordRules
    {
        public const int MinLength = 8;

        /// <summary>Возвращает сообщение об ошибке или null, если пароль годится.</summary>
        public static string Check(string password, string confirmation)
        {
            if (string.IsNullOrEmpty(password))
            {
                return "Введите мастер-пароль.";
            }
            if (password.Length < MinLength)
            {
                return string.Format("Мастер-пароль должен быть не короче {0} символов.", MinLength);
            }
            if (password != confirmation)
            {
                return "Пароли не совпадают. Введите одинаковый пароль в оба поля.";
            }
            return null;
        }

        /// <summary>Подсказка под полем нового мастер-пароля.</summary>
        public static string Hint(string password, out Color color)
        {
            int length = string.IsNullOrEmpty(password) ? 0 : password.Length;
            if (length == 0)
            {
                color = Ui.Muted;
                return string.Format("Не короче {0} символов. Лучше всего — фраза из нескольких слов.", MinLength);
            }
            if (length < MinLength)
            {
                color = Ui.Danger;
                return string.Format("Слишком короткий: нужно ещё {0}.",
                    Ui.Plural(MinLength - length, "символ", "символа", "символов"));
            }
            if (IsTrivial(password))
            {
                color = Ui.Danger;
                return "Такой пароль легко подобрать: добавьте буквы или слова.";
            }
            if (length < 12)
            {
                color = Ui.Muted;
                return "Подходит. Надёжнее — от 12 символов.";
            }
            color = Ui.Success;
            return length < 16 ? "Хорошая длина." : "Отличная длина.";
        }

        /// <summary>Одни цифры или один повторяющийся символ.</summary>
        private static bool IsTrivial(string password)
        {
            bool allDigits = true;
            bool allSame = true;
            foreach (char c in password)
            {
                if (!char.IsDigit(c)) allDigits = false;
                if (c != password[0]) allSame = false;
            }
            return allSame || (allDigits && password.Length < 14);
        }
    }
}
