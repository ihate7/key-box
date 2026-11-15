using System;
using System.Drawing;
using System.Windows.Forms;
using KeyBox.Crypto;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>
    /// Настройки. Они хранятся внутри хранилища (зашифрованными, как всё остальное) и переезжают
    /// вместе с ним: на компьютере программа по-прежнему ничего не оставляет.
    /// Само хранилище окно не меняет — оно только возвращает выбранные значения.
    /// </summary>
    internal sealed class SettingsForm : DialogForm
    {
        private sealed class Choice
        {
            public int Value;
            public string Code;
            public string Text;

            public override string ToString()
            {
                return Text;
            }
        }

        private static readonly int[] AutoLockChoices = { 1, 2, 5, 10, 15, 30, 60, 0 };
        private static readonly int[] ClipboardChoices = { 10, 20, 30, 60, 120, 300 };

        private readonly VaultSettings original;
        private readonly ComboBox cmbLanguage;
        private readonly ComboBox cmbAutoLock;
        private readonly ComboBox cmbClipboard;
        private readonly NumericUpDown numLength;
        private readonly CheckBox chkUpper;
        private readonly CheckBox chkLower;
        private readonly CheckBox chkDigits;
        private readonly CheckBox chkSymbols;
        private readonly CheckBox chkNoLookAlikes;
        private readonly Label lblSample;
        private readonly CheckBox chkAutoTypeEnter;
        private readonly Label lblError;

        public SettingsForm(VaultSettings settings)
            : base(L.T("Настройки", "Settings"), 540)
        {
            original = settings.Clone();
            Name = "SettingsForm";

            Body.ColumnCount = 2;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            // --- Общие
            AddSection(L.T("Общие", "General"), true);
            cmbLanguage = MakeCombo("cmbLanguage");
            AddChoice(cmbLanguage, 0, null, L.T("Как в Windows", "Same as Windows"));
            AddChoice(cmbLanguage, 0, "ru", L.Native("Русский"));
            AddChoice(cmbLanguage, 0, "en", L.Native("English"));
            SelectCode(cmbLanguage, settings.Language);
            AddRow(L.T("Язык", "Language"), cmbLanguage);

            // --- Безопасность
            AddSection(L.T("Безопасность", "Security"), false);
            cmbAutoLock = MakeCombo("cmbAutoLock");
            FillNumbers(cmbAutoLock, AutoLockChoices, settings.AutoLockMinutes, DescribeAutoLock);
            AddRow(L.T("Блокировать при бездействии", "Lock when idle"), cmbAutoLock);

            cmbClipboard = MakeCombo("cmbClipboard");
            FillNumbers(cmbClipboard, ClipboardChoices, settings.ClipboardSeconds, DescribeClipboard);
            AddRow(L.T("Очищать буфер обмена", "Clear the clipboard"), cmbClipboard);

            // --- Генератор паролей
            AddSection(L.T("Генератор паролей", "Password generator"), false);
            numLength = new NumericUpDown();
            numLength.Name = "numLength";
            numLength.Font = Ui.Font;
            numLength.Minimum = VaultSettings.MinPasswordLength;
            numLength.Maximum = VaultSettings.MaxPasswordLength;
            numLength.Value = Math.Max(VaultSettings.MinPasswordLength, Math.Min(VaultSettings.MaxPasswordLength, settings.PasswordLength));
            numLength.Width = Ui.S(72);
            numLength.Anchor = AnchorStyles.Left;
            numLength.Margin = new Padding(0, 0, 0, Ui.S(10));
            numLength.ValueChanged += delegate { OnGeneratorChanged(); };
            AddRow(L.T("Длина пароля", "Password length"), numLength);

            var classes = new FlowLayoutPanel();
            classes.FlowDirection = FlowDirection.TopDown;
            classes.WrapContents = false;
            classes.AutoSize = true;
            classes.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            classes.Anchor = AnchorStyles.Left;
            classes.Margin = new Padding(0, 0, 0, Ui.S(10));
            chkUpper = MakeCheck("chkUpper", L.T("Прописные буквы (A–Z)", "Uppercase letters (A–Z)"), settings.PasswordUpper, true);
            chkLower = MakeCheck("chkLower", L.T("Строчные буквы (a–z)", "Lowercase letters (a–z)"), settings.PasswordLower, true);
            chkDigits = MakeCheck("chkDigits", L.T("Цифры (0–9)", "Digits (0–9)"), settings.PasswordDigits, true);
            chkSymbols = MakeCheck("chkSymbols", L.T("Знаки (!@#$%…)", "Symbols (!@#$%…)"), settings.PasswordSymbols, true);
            chkNoLookAlikes = MakeCheck("chkNoLookAlikes", L.T("Без похожих символов: O и 0, l и 1", "No look-alike characters: O and 0, l and 1"),
                settings.PasswordNoLookAlikes, true);
            classes.Controls.AddRange(new Control[] { chkUpper, chkLower, chkDigits, chkSymbols, chkNoLookAlikes });
            AddRow(L.T("Символы", "Characters"), classes, true);

            lblSample = Ui.MakeLabel("");
            lblSample.Name = "lblSample";
            lblSample.Font = Ui.MonoFont;
            lblSample.AutoSize = false;
            lblSample.AutoEllipsis = true;
            lblSample.Height = Ui.MonoFont.Height + Ui.S(2);
            lblSample.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            lblSample.Margin = Padding.Empty;
            AddRow(L.T("Пример", "Sample"), lblSample);

            // --- Автоввод
            AddSection(L.T("Автоввод", "Auto-type"), false);
            chkAutoTypeEnter = MakeCheck("chkAutoTypeEnter", L.T("Нажимать Enter после ввода пароля", "Press Enter after typing the password"),
                settings.AutoTypeEnter, false);
            Body.Controls.Add(chkAutoTypeEnter);
            Body.SetColumnSpan(chkAutoTypeEnter, 2);

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(12), 0, 0);
            Body.Controls.Add(lblError);
            Body.SetColumnSpan(lblError, 2);

            Button ok = Ui.MakeButton(L.T("Сохранить", "Save"));
            ok.Name = "btnOk";
            ok.Click += OnOk;
            Button cancel = Ui.MakeButton(L.T("Отмена", "Cancel"));
            cancel.Name = "btnCancel";
            cancel.DialogResult = DialogResult.Cancel;
            SetButtons(ok, cancel, false);

            ActiveControl = cmbLanguage;
            OnGeneratorChanged();
        }

        /// <summary>Выбранные значения.</summary>
        public VaultSettings Settings
        {
            get
            {
                VaultSettings settings = original.Clone();
                settings.Language = ((Choice)cmbLanguage.SelectedItem).Code;
                settings.AutoLockMinutes = ((Choice)cmbAutoLock.SelectedItem).Value;
                settings.ClipboardSeconds = ((Choice)cmbClipboard.SelectedItem).Value;
                settings.PasswordLength = (int)numLength.Value;
                settings.PasswordUpper = chkUpper.Checked;
                settings.PasswordLower = chkLower.Checked;
                settings.PasswordDigits = chkDigits.Checked;
                settings.PasswordSymbols = chkSymbols.Checked;
                settings.PasswordNoLookAlikes = chkNoLookAlikes.Checked;
                settings.AutoTypeEnter = chkAutoTypeEnter.Checked;
                return settings;
            }
        }

        private static string DescribeAutoLock(int minutes)
        {
            return minutes == 0
                ? L.T("не блокировать", "never")
                : L.F("через {0}", "after {0}", L.Plural(minutes, "минуту", "минуты", "минут", "minute", "minutes"));
        }

        private static string DescribeClipboard(int seconds)
        {
            return L.F("через {0}", "after {0}", L.Plural(seconds, "секунду", "секунды", "секунд", "second", "seconds"));
        }

        private void AddSection(string title, bool first)
        {
            Label label = Ui.MakeLabel(title);
            label.Font = Ui.BoldFont;
            label.Margin = new Padding(0, first ? 0 : Ui.S(16), 0, Ui.S(10));
            Body.Controls.Add(label);
            Body.SetColumnSpan(label, 2);
        }

        private void AddRow(string caption, Control field)
        {
            AddRow(caption, field, false);
        }

        private void AddRow(string caption, Control field, bool alignTop)
        {
            Label label = Ui.MakeLabel(caption);
            if (alignTop)
            {
                label.Anchor = AnchorStyles.Left | AnchorStyles.Top;
                label.Margin = new Padding(0, Ui.S(2), Ui.S(16), 0);
            }
            else
            {
                label.Anchor = AnchorStyles.Left;
                label.Margin = new Padding(0, 0, Ui.S(16), field.Margin.Bottom);
            }
            Body.Controls.Add(label);
            Body.Controls.Add(field);
        }

        private static ComboBox MakeCombo(string name)
        {
            var combo = new ComboBox();
            combo.Name = name;
            combo.DropDownStyle = ComboBoxStyle.DropDownList;
            // Высота задаётся сразу: настоящую список получает только при создании окна.
            combo.Font = Ui.Font;
            combo.Height = combo.PreferredHeight;
            combo.Width = Ui.S(230);
            combo.Anchor = AnchorStyles.Left;
            combo.Margin = new Padding(0, 0, 0, Ui.S(10));
            return combo;
        }

        private CheckBox MakeCheck(string name, string text, bool value, bool affectsSample)
        {
            var box = new CheckBox();
            box.Name = name;
            box.Text = text;
            box.Checked = value;
            box.AutoSize = true;
            box.UseMnemonic = false;
            box.Margin = new Padding(0, 0, 0, Ui.S(4));
            if (affectsSample) box.CheckedChanged += delegate { OnGeneratorChanged(); };
            return box;
        }

        private static void AddChoice(ComboBox combo, int value, string code, string text)
        {
            var choice = new Choice();
            choice.Value = value;
            choice.Code = code;
            choice.Text = text;
            combo.Items.Add(choice);
        }

        private static void SelectCode(ComboBox combo, string code)
        {
            combo.SelectedIndex = 0;
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (((Choice)combo.Items[i]).Code == code) combo.SelectedIndex = i;
            }
        }

        /// <summary>
        /// Заполняет список числовых значений. Если в хранилище сохранено значение не из списка
        /// (например, его задала другая версия программы), оно добавляется, а не теряется.
        /// </summary>
        private static void FillNumbers(ComboBox combo, int[] values, int current, Func<int, string> describe)
        {
            bool known = Array.IndexOf(values, current) >= 0;
            foreach (int value in values)
            {
                // Значение не из списка встаёт по порядку; «никогда» (0) всегда последнее.
                if (!known && current > 0 && (value == 0 || value > current))
                {
                    AddChoice(combo, current, null, describe(current));
                    known = true;
                }
                AddChoice(combo, value, null, describe(value));
            }
            if (!known) AddChoice(combo, current, null, describe(current));

            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (((Choice)combo.Items[i]).Value == current) combo.SelectedIndex = i;
            }
        }

        private bool AnyClass
        {
            get { return chkUpper.Checked || chkLower.Checked || chkDigits.Checked || chkSymbols.Checked; }
        }

        private void OnGeneratorChanged()
        {
            if (lblSample == null) return; // окно ещё строится
            Ui.ShowError(lblError, null);
            if (!AnyClass)
            {
                lblSample.Text = "—";
                return;
            }
            lblSample.Text = PasswordGenerator.Generate((int)numLength.Value, chkUpper.Checked, chkLower.Checked,
                chkDigits.Checked, chkSymbols.Checked, chkNoLookAlikes.Checked);
        }

        private void OnOk(object sender, EventArgs e)
        {
            if (!AnyClass)
            {
                Ui.ShowError(lblError, L.T("Выберите, из чего составлять пароли: буквы, цифры или знаки.",
                                           "Choose what passwords are made of: letters, digits or symbols."));
                chkUpper.Focus();
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
