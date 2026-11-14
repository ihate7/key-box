using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeyBox.Crypto;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>
    /// Создание и изменение записи: описание, логин, пароль и группа.
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

        private readonly TextBox txtDescription;
        private readonly TextBox txtLogin;
        private readonly TextBox txtPassword;
        private readonly CheckBox chkShow;
        private readonly Button btnGenerate;
        private readonly ComboBox cmbGroup;
        private readonly Label lblError;

        /// <param name="data">Хранилище — из него берётся список групп.</param>
        /// <param name="entry">Изменяемая запись или null для новой.</param>
        /// <param name="groupId">Группа, выбранная изначально (null — без группы).</param>
        public EntryForm(VaultData data, Entry entry, string groupId)
            : base(entry == null ? "Новая запись" : "Изменение записи", 540)
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
            AddRow("Описание", txtDescription, true);

            // Логин
            txtLogin = new TextBox();
            txtLogin.Name = "txtLogin";
            txtLogin.MaxLength = VaultData.MaxLoginLength;
            txtLogin.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtLogin.Margin = new Padding(0, 0, 0, gap);
            AddRow("Логин", txtLogin, false);

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

            btnGenerate = Ui.MakeButton("Сгенерировать");
            btnGenerate.Name = "btnGenerate";
            btnGenerate.MinimumSize = new Size(0, txtPassword.PreferredHeight);
            btnGenerate.Margin = new Padding(Ui.S(6), 0, 0, 0);
            btnGenerate.Click += OnGenerate;

            passwordRow.Controls.Add(txtPassword, 0, 0);
            passwordRow.Controls.Add(chkShow, 1, 0);
            passwordRow.Controls.Add(btnGenerate, 2, 0);
            AddRow("Пароль", passwordRow, false);

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
            AddRow("Группа", cmbGroup, false);

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(12), 0, 0);
            Body.Controls.Add(lblError);
            Body.SetColumnSpan(lblError, 2);

            var tips = new ToolTip();
            tips.SetToolTip(chkShow, "Показать пароль");
            tips.SetToolTip(btnGenerate, string.Format("Случайный пароль из {0} символов", PasswordGenerator.DefaultLength));
            Disposed += delegate { tips.Dispose(); };

            if (entry != null)
            {
                txtDescription.Text = (entry.Description ?? "").Replace("\n", "\r\n");
                txtLogin.Text = entry.Login;
                txtPassword.Text = entry.Password;

                string times = DescribeTimes(entry);
                if (times != null)
                {
                    Label info = Ui.MakeWrapLabel(times, ContentWidth, Ui.Muted);
                    info.Font = Ui.SmallFont;
                    info.Margin = new Padding(0, Ui.S(12), 0, 0);
                    Body.Controls.Add(info);
                    Body.SetColumnSpan(info, 2);
                }
            }

            Button ok = Ui.MakeButton(entry == null ? "Добавить" : "Сохранить");
            ok.Name = "btnOk";
            ok.Click += OnOk;
            Button cancel = Ui.MakeButton("Отмена");
            cancel.Name = "btnCancel";
            cancel.DialogResult = DialogResult.Cancel;
            SetButtons(ok, cancel, false);

            ActiveControl = txtDescription;
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

        private void FillGroups(VaultData data, string selectedId)
        {
            var groups = new List<Group>(data.Groups);
            groups.Sort(delegate(Group a, Group b) { return Ui.CompareNatural(a.Name, b.Name); });

            var none = new GroupChoice();
            none.Id = null;
            none.Name = "Без группы";
            cmbGroup.Items.Add(none);
            cmbGroup.SelectedIndex = 0;

            foreach (Group group in groups)
            {
                var choice = new GroupChoice();
                choice.Id = group.Id;
                choice.Name = group.Name;
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
                return "Создано " + Ui.FormatTime(created);
            }
            if (!hasCreated)
            {
                return "Изменено " + Ui.FormatTime(modified);
            }
            return "Создано " + Ui.FormatTime(created) + "  ·  изменено " + Ui.FormatTime(modified);
        }

        private void OnShowChanged(object sender, EventArgs e)
        {
            txtPassword.UseSystemPasswordChar = !chkShow.Checked;
            txtPassword.Font = chkShow.Checked ? Ui.MonoFont : Ui.Font;
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
            string problem = VaultData.ValidateEntry(Login, Password, Description);
            if (problem != null)
            {
                Ui.ShowError(lblError, problem);
                txtDescription.Focus();
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
