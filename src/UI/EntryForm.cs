using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeyBox.Crypto;
using KeyBox.Vault;
using FormsTimer = System.Windows.Forms.Timer;

namespace KeyBox.UI
{
    /// <summary>
    /// Создание и изменение записи: описание, сайт, логин, пароль, ключ одноразовых кодов и группа.
    /// Само хранилище окно не меняет — оно только возвращает введённые значения.
    /// </summary>
    internal sealed class EntryForm : DialogForm
    {
        private sealed class GroupChoice
        {
            public string Id;
            public string Name;

            public override string ToString()
            {
                return Name;
            }
        }

        private readonly FormsTimer codeTimer = new FormsTimer();
        private readonly TextBox txtDescription;
        private readonly TextBox txtUrl;
        private readonly TextBox txtLogin;
        private readonly TextBox txtPassword;
        private readonly CheckBox chkShow;
        private readonly Button btnGenerate;
        private readonly TextBox txtTotp;
        private readonly Label lblTotp;
        private readonly ComboBox cmbGroup;
        private readonly Label lblError;

        /// <param name="data">Хранилище — из него берётся список групп.</param>
        /// <param name="entry">Изменяемая запись или null для новой.</param>
        /// <param name="groupId">Группа, выбранная изначально (null — без группы).</param>
        public EntryForm(VaultData data, Entry entry, string groupId)
            : base(entry == null ? L.T("Новая запись", "New entry") : L.T("Изменение записи", "Edit entry"), 560)
        {
            Name = "EntryForm";

            Body.ColumnCount = 2;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            int gap = Ui.S(12);

            // Описание
            txtDescription = new TextBox();
            txtDescription.Name = "txtDescription";
            txtDescription.Multiline = true;
            txtDescription.AcceptsReturn = true;
            txtDescription.ScrollBars = ScrollBars.Vertical;
            txtDescription.MaxLength = VaultData.MaxDescriptionLength;
            txtDescription.Height = Ui.Font.Height * 3 + Ui.S(10);
            txtDescription.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtDescription.Margin = new Padding(0, 0, 0, gap);
            AddRow(L.T("Описание", "Description"), txtDescription, true);

            // Сайт
            txtUrl = new TextBox();
            txtUrl.Name = "txtUrl";
            txtUrl.MaxLength = VaultData.MaxUrlLength;
            txtUrl.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtUrl.Margin = new Padding(0, 0, 0, gap);
            SetCue(txtUrl, "example.com");
            AddRow(L.T("Сайт", "Website"), txtUrl, false);

            // Логин
            txtLogin = new TextBox();
            txtLogin.Name = "txtLogin";
            txtLogin.MaxLength = VaultData.MaxLoginLength;
            txtLogin.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtLogin.Margin = new Padding(0, 0, 0, gap);
            AddRow(L.T("Логин", "Username"), txtLogin, false);

            // Пароль: поле, «показать», «сгенерировать»
            var passwordRow = new TableLayoutPanel();
            passwordRow.AutoSize = true;
            passwordRow.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            passwordRow.ColumnCount = 3;
            passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            passwordRow.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            passwordRow.Margin = new Padding(0, 0, 0, gap);

            txtPassword = new TextBox();
            txtPassword.Name = "txtPassword";
            txtPassword.Font = Ui.Font;   // шрифт задаётся сразу: по нему считается высота кнопок рядом
            txtPassword.UseSystemPasswordChar = true;
            txtPassword.MaxLength = VaultData.MaxPasswordLength;
            txtPassword.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtPassword.Margin = Padding.Empty;

            chkShow = Ui.MakeEyeToggle(txtPassword.PreferredHeight);
            chkShow.Name = "chkShow";
            chkShow.CheckedChanged += OnShowChanged;

            btnGenerate = Ui.MakeButton(L.T("Сгенерировать", "Generate"));
            btnGenerate.Name = "btnGenerate";
            btnGenerate.MinimumSize = new Size(0, txtPassword.PreferredHeight);
            btnGenerate.Margin = new Padding(Ui.S(6), 0, 0, 0);
            btnGenerate.Click += OnGenerate;

            passwordRow.Controls.Add(txtPassword, 0, 0);
            passwordRow.Controls.Add(chkShow, 1, 0);
            passwordRow.Controls.Add(btnGenerate, 2, 0);
            AddRow(L.T("Пароль", "Password"), passwordRow, false);

            // Ключ одноразовых кодов: поле и строка под ним — подсказка, текущий код или ошибка.
            var totpPanel = new TableLayoutPanel();
            totpPanel.AutoSize = true;
            totpPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            totpPanel.ColumnCount = 1;
            totpPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            totpPanel.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            totpPanel.Margin = new Padding(0, 0, 0, gap);

            txtTotp = new TextBox();
            txtTotp.Name = "txtTotp";
            txtTotp.UseSystemPasswordChar = true;
            txtTotp.MaxLength = VaultData.MaxTotpLength;
            txtTotp.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtTotp.Margin = Padding.Empty;
            txtTotp.TextChanged += delegate { UpdateCodePreview(); };
            SetCue(txtTotp, L.T("ключ с сайта или ссылка otpauth://", "key from the website or an otpauth:// link"));

            lblTotp = Ui.MakeWrapLabel("", Ui.S(400), Ui.Muted);
            lblTotp.Name = "lblTotp";
            lblTotp.Font = Ui.SmallFont;
            lblTotp.Margin = new Padding(0, Ui.S(4), 0, 0);

            totpPanel.Controls.Add(txtTotp, 0, 0);
            totpPanel.Controls.Add(lblTotp, 0, 1);
            AddRow(L.T("Ключ 2FA", "2FA key"), totpPanel, true);

            // Группа
            cmbGroup = new ComboBox();
            cmbGroup.Name = "cmbGroup";
            // Раскладка берёт заданную высоту списка, а настоящую он получает от Windows только
            // при создании окна. Задаём её сразу, иначе при крупном масштабе экрана список
            // сползает вниз относительно своей подписи.
            cmbGroup.Font = Ui.Font;
            cmbGroup.Height = cmbGroup.PreferredHeight;
            cmbGroup.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbGroup.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            cmbGroup.Margin = Padding.Empty;
            cmbGroup.MaxDropDownItems = 16;
            FillGroups(data, groupId);
            AddRow(L.T("Группа", "Group"), cmbGroup, false);

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(12), 0, 0);
            Body.Controls.Add(lblError);
            Body.SetColumnSpan(lblError, 2);

            // Замечание относится к прежнему вводу: стоит что-нибудь изменить — и оно убирается.
            EventHandler clearError = delegate { Ui.ShowError(lblError, null); };
            foreach (TextBox box in new[] { txtDescription, txtUrl, txtLogin, txtPassword, txtTotp })
            {
                box.TextChanged += clearError;
            }

            var tips = new ToolTip();
            tips.SetToolTip(chkShow, L.T("Показать пароль и ключ", "Show the password and the key"));
            tips.SetToolTip(btnGenerate, L.F("Случайный пароль из {0} символов", "Random password of {0} characters", PasswordGenerator.DefaultLength));

            codeTimer.Interval = 1000;
            codeTimer.Tick += delegate { UpdateCodePreview(); };
            Disposed += delegate
            {
                tips.Dispose();
                codeTimer.Dispose();
            };

            if (entry != null)
            {
                txtDescription.Text = (entry.Description ?? "").Replace("\n", "\r\n");
                txtUrl.Text = entry.Url ?? "";
                txtLogin.Text = entry.Login;
                txtPassword.Text = entry.Password;
                txtTotp.Text = entry.Totp ?? "";

                string times = DescribeTimes(entry);
                if (entry.History != null && entry.History.Count > 0)
                {
                    string history = L.F("прежних паролей: {0} (см. меню записи)", "previous passwords: {0} (see the entry menu)", entry.History.Count);
                    times = times == null ? history : times + "  ·  " + history;
                }
                if (times != null)
                {
                    Label info = Ui.MakeWrapLabel(times, ContentWidth, Ui.Muted);
                    info.Font = Ui.SmallFont;
                    info.Margin = new Padding(0, Ui.S(12), 0, 0);
                    Body.Controls.Add(info);
                    Body.SetColumnSpan(info, 2);
                }
            }

            Button ok = Ui.MakeButton(entry == null ? L.T("Добавить", "Add") : L.T("Сохранить", "Save"));
            ok.Name = "btnOk";
            ok.Click += OnOk;
            Button cancel = Ui.MakeButton(L.T("Отмена", "Cancel"));
            cancel.Name = "btnCancel";
            cancel.DialogResult = DialogResult.Cancel;
            SetButtons(ok, cancel, false);

            ActiveControl = txtDescription;
            UpdateCodePreview();
        }

        public string Description
        {
            get { return txtDescription.Text; }
        }

        public string Login
        {
            get { return txtLogin.Text; }
        }

        public string Password
        {
            get { return txtPassword.Text; }
        }

        /// <summary>Выбранная группа; null — без группы.</summary>
        public string GroupId
        {
            get
            {
                var choice = cmbGroup.SelectedItem as GroupChoice;
                return choice == null ? null : choice.Id;
            }
        }

        /// <summary>Все введённые значения разом.</summary>
        public EntryFields Fields
        {
            get
            {
                var fields = new EntryFields();
                fields.GroupId = GroupId;
                fields.Login = Login;
                fields.Password = Password;
                fields.Description = Description;
                fields.Url = txtUrl.Text;
                fields.Totp = txtTotp.Text;
                return fields;
            }
        }

        private void AddRow(string caption, Control field, bool alignTop)
        {
            Label label = Ui.MakeLabel(caption);
            if (alignTop)
            {
                label.Anchor = AnchorStyles.Left | AnchorStyles.Top;
                label.Margin = new Padding(0, Ui.S(4), Ui.S(14), 0);
            }
            else
            {
                // Подпись по вертикали — на уровне поля; нижний отступ поля в расчёт не идёт.
                label.Anchor = AnchorStyles.Left;
                label.Margin = new Padding(0, 0, Ui.S(14), field.Margin.Bottom);
            }
            Body.Controls.Add(label);
            Body.Controls.Add(field);
        }

        /// <summary>Бледная подсказка в пустом поле ввода.</summary>
        private static void SetCue(TextBox box, string text)
        {
            box.HandleCreated += delegate
            {
                NativeMethods.SendMessage(box.Handle, NativeMethods.EM_SETCUEBANNER, (IntPtr)1, text);
            };
        }

        private void FillGroups(VaultData data, string selectedId)
        {
            // Группы идут в порядке дерева и показаны полным путём: «Работа / Проекты».
            List<Group> groups = data.TreeOrder(Ui.CompareNatural);

            var none = new GroupChoice();
            none.Id = null;
            none.Name = L.T("Без группы", "No group");
            cmbGroup.Items.Add(none);
            cmbGroup.SelectedIndex = 0;

            foreach (Group group in groups)
            {
                var choice = new GroupChoice();
                choice.Id = group.Id;
                choice.Name = data.GroupPath(group.Id);
                cmbGroup.Items.Add(choice);
                if (group.Id == selectedId)
                {
                    cmbGroup.SelectedIndex = cmbGroup.Items.Count - 1;
                }
            }
        }

        private static string DescribeTimes(Entry entry)
        {
            DateTime created;
            DateTime modified;
            bool hasCreated = VaultData.TryParseTimestamp(entry.Created, out created);
            bool hasModified = VaultData.TryParseTimestamp(entry.Modified, out modified);
            if (!hasCreated && !hasModified) return null;
            if (hasCreated && (!hasModified || entry.Created == entry.Modified))
            {
                return L.T("Создано ", "Created ") + L.FormatTime(created);
            }
            if (!hasCreated)
            {
                return L.T("Изменено ", "Modified ") + L.FormatTime(modified);
            }
            return L.T("Создано ", "Created ") + L.FormatTime(created) + L.T("  ·  изменено ", "  ·  modified ") + L.FormatTime(modified);
        }

        /// <summary>Строка под ключом: подсказка, пока поле пустое; ошибка, если ключ не разобран; иначе — текущий код.</summary>
        private void UpdateCodePreview()
        {
            string text = txtTotp.Text.Trim();
            if (text.Length == 0)
            {
                codeTimer.Stop();
                lblTotp.ForeColor = Ui.Muted;
                lblTotp.Text = L.T("Необязательно: секретный ключ двухфакторной защиты — для одноразовых кодов.",
                                   "Optional: the secret key of two-factor protection, for one-time codes.");
                return;
            }

            TotpKey key = Totp.Parse(text);
            if (key == null)
            {
                codeTimer.Stop();
                lblTotp.ForeColor = Ui.Danger;
                lblTotp.Text = L.T("Ключ не распознан: нужны буквы A–Z и цифры 2–7 или ссылка otpauth://.",
                                   "The key is not recognised: use letters A–Z and digits 2–7, or an otpauth:// link.");
                return;
            }

            DateTime now = DateTime.UtcNow;
            lblTotp.ForeColor = Ui.Success;
            lblTotp.Text = L.F("Код сейчас: {0} · сменится через {1} с", "Code now: {0} · changes in {1} s",
                Totp.Readable(Totp.Code(key, now)), Totp.SecondsLeft(key, now));
            codeTimer.Start();
        }

        private void OnShowChanged(object sender, EventArgs e)
        {
            txtPassword.UseSystemPasswordChar = !chkShow.Checked;
            txtPassword.Font = chkShow.Checked ? Ui.MonoFont : Ui.Font;
            txtTotp.UseSystemPasswordChar = !chkShow.Checked;
        }

        private void OnGenerate(object sender, EventArgs e)
        {
            txtPassword.Text = PasswordGenerator.Generate(PasswordGenerator.DefaultLength);
            chkShow.Checked = true;
            txtPassword.Focus();
            txtPassword.SelectAll();
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            // В поле описания Enter переводит строку, поэтому сохранить запись, не уходя
            // с клавиатуры, можно сочетанием Ctrl+Enter.
            if (keyData == (Keys.Control | Keys.Enter))
            {
                OnOk(this, EventArgs.Empty);
                return true;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        private void OnOk(object sender, EventArgs e)
        {
            string problem = VaultData.ValidateEntry(Fields);
            if (problem != null)
            {
                Ui.ShowError(lblError, problem);
                // Курсор — в поле, к которому относится замечание.
                Control field = txtDescription;
                if (VaultData.ValidateEntry(Login, Password, Description) == null)
                {
                    field = txtUrl.Text.Trim().Length > VaultData.MaxUrlLength ? txtUrl : txtTotp;
                }
                field.Focus();
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
