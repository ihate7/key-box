using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>
    /// Вход в программу: ввод мастер-пароля существующего хранилища
    /// либо создание нового хранилища, если файла ещё нет.
    /// </summary>
    internal sealed class UnlockForm : DialogForm
    {
        private readonly string vaultPath;
        private readonly bool createMode;
        private readonly TextBox txtPassword;
        private readonly TextBox txtConfirm;
        private readonly bool needsKeyFile;
        private readonly TextBox txtKeyFile;
        private readonly Button btnKeyFile;
        private readonly CheckBox chkShow;
        private readonly Label lblHint;
        private readonly Label lblError;
        private readonly Button btnOk;
        private readonly Button btnCancel;
        private VaultSession session;
        private bool busy;

        /// <summary>
        /// Путь к ключевому файлу, которым хранилище открывали в прошлый раз (или заданный
        /// в командной строке). Помнится только пока программа запущена — на диск не пишется.
        /// </summary>
        internal static string LastKeyFile { get; set; }

        public UnlockForm(string vaultPath)
            : base(Program.AppName, 430)
        {
            this.vaultPath = vaultPath;
            createMode = !File.Exists(vaultPath);

            // Нужен ли ключевой файл, записано в заголовке хранилища — его можно прочитать без пароля.
            VaultHeader fileHeader = createMode ? null : VaultSession.Peek(vaultPath);
            needsKeyFile = fileHeader != null && fileHeader.Kdf.KeyFile;

            Name = "UnlockForm";
            ShowInTaskbar = true;
            ShowIcon = true;
            MinimizeBox = true;
            StartPosition = FormStartPosition.CenterScreen;

            Body.ColumnCount = 1;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            // Шапка: логотип, название, пояснение.
            var header = new TableLayoutPanel();
            header.AutoSize = true;
            header.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            header.ColumnCount = 2;
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            header.Margin = new Padding(0, 0, 0, Ui.S(18));

            var logo = new PictureBox();
            logo.Size = new Size(Ui.S(44), Ui.S(44));
            logo.SizeMode = PictureBoxSizeMode.Zoom;
            logo.Image = Ui.Logo(44);
            logo.Margin = new Padding(0, 0, Ui.S(12), 0);

            var titles = new FlowLayoutPanel();
            titles.FlowDirection = FlowDirection.TopDown;
            titles.WrapContents = false;
            titles.AutoSize = true;
            titles.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            titles.Margin = Padding.Empty;
            titles.Anchor = AnchorStyles.Left;

            Label title = Ui.MakeLabel(Program.AppName);
            title.Font = Ui.TitleFont;
            Label subtitle = Ui.MakeLabel(createMode ? L.T("Создание нового хранилища паролей", "Create a new password vault") : L.T("Хранилище заблокировано", "The vault is locked"));
            subtitle.Name = "lblSubtitle";
            subtitle.ForeColor = Ui.Muted;
            subtitle.Margin = new Padding(Ui.S(2), 0, 0, 0);
            titles.Controls.Add(title);
            titles.Controls.Add(subtitle);

            header.Controls.Add(logo, 0, 0);
            header.Controls.Add(titles, 1, 0);
            Body.Controls.Add(header);

            // Мастер-пароль и кнопка «показать».
            Body.Controls.Add(Ui.MakeLabel(createMode ? L.T("Придумайте мастер-пароль", "Choose a master password") : L.T("Мастер-пароль", "Master password")));

            var passwordRow = new TableLayoutPanel();
            passwordRow.AutoSize = true;
            passwordRow.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            passwordRow.ColumnCount = 2;
            passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            passwordRow.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            passwordRow.Margin = new Padding(0, Ui.S(6), 0, 0);

            txtPassword = new TextBox();
            txtPassword.Name = "txtPassword";
            txtPassword.Font = Ui.Font;   // шрифт задаётся сразу: по нему считается высота кнопки рядом
            txtPassword.UseSystemPasswordChar = true;
            txtPassword.MaxLength = 1024;
            txtPassword.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtPassword.Margin = Padding.Empty;
            txtPassword.TextChanged += OnPasswordChanged;

            chkShow = Ui.MakeEyeToggle(txtPassword.PreferredHeight);
            chkShow.Name = "chkShow";
            chkShow.TabStop = false;
            chkShow.CheckedChanged += OnShowChanged;
            var tips = new ToolTip();
            tips.SetToolTip(chkShow, L.T("Показать пароль", "Show password"));
            Disposed += delegate { tips.Dispose(); };

            passwordRow.Controls.Add(txtPassword, 0, 0);
            passwordRow.Controls.Add(chkShow, 1, 0);
            Body.Controls.Add(passwordRow);

            if (createMode)
            {
                Label confirmLabel = Ui.MakeLabel(L.T("Повторите мастер-пароль", "Repeat the master password"));
                confirmLabel.Margin = new Padding(0, Ui.S(12), 0, 0);
                Body.Controls.Add(confirmLabel);

                txtConfirm = new TextBox();
                txtConfirm.Name = "txtConfirm";
                txtConfirm.UseSystemPasswordChar = true;
                txtConfirm.MaxLength = 1024;
                txtConfirm.Anchor = AnchorStyles.Left | AnchorStyles.Right;
                txtConfirm.Margin = new Padding(0, Ui.S(6), 0, 0);
                txtConfirm.TextChanged += OnPasswordChanged;
                Body.Controls.Add(txtConfirm);

                lblHint = Ui.MakeWrapLabel("", ContentWidth, Ui.Muted);
                lblHint.Name = "lblHint";
                lblHint.Margin = new Padding(0, Ui.S(8), 0, 0);
                Body.Controls.Add(lblHint);

                Label warning = Ui.MakeWrapLabel(
                    L.T("Запомните мастер-пароль: восстановить его нельзя. Без него открыть хранилище не сможет никто — в том числе и вы.", "Remember the master password: it cannot be recovered. Without it nobody can open the vault — including you."),
                    ContentWidth, Ui.TextColor);
                warning.Margin = new Padding(0, Ui.S(12), 0, 0);
                Body.Controls.Add(warning);
            }

            if (needsKeyFile)
            {
                Label keyLabel = Ui.MakeLabel(L.T("Ключевой файл", "Key file"));
                keyLabel.Margin = new Padding(0, Ui.S(12), 0, 0);
                Body.Controls.Add(keyLabel);

                var keyRow = new TableLayoutPanel();
                keyRow.AutoSize = true;
                keyRow.AutoSizeMode = AutoSizeMode.GrowAndShrink;
                keyRow.ColumnCount = 2;
                keyRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
                keyRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
                keyRow.Anchor = AnchorStyles.Left | AnchorStyles.Right;
                keyRow.Margin = new Padding(0, Ui.S(6), 0, 0);

                txtKeyFile = new TextBox();
                txtKeyFile.Name = "txtKeyFile";
                txtKeyFile.Font = Ui.Font;
                txtKeyFile.ReadOnly = true;
                txtKeyFile.TabStop = false;
                txtKeyFile.Anchor = AnchorStyles.Left | AnchorStyles.Right;
                txtKeyFile.Margin = Padding.Empty;
                if (!string.IsNullOrEmpty(LastKeyFile) && File.Exists(LastKeyFile)) txtKeyFile.Text = LastKeyFile;

                btnKeyFile = Ui.MakeButton(L.T("Выбрать…", "Choose…"));
                btnKeyFile.Name = "btnKeyFile";
                btnKeyFile.MinimumSize = new Size(0, txtKeyFile.PreferredHeight);
                btnKeyFile.Margin = new Padding(Ui.S(6), 0, 0, 0);
                btnKeyFile.Click += OnChooseKeyFile;

                keyRow.Controls.Add(txtKeyFile, 0, 0);
                keyRow.Controls.Add(btnKeyFile, 1, 0);
                Body.Controls.Add(keyRow);
            }

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(10), 0, 0);
            Body.Controls.Add(lblError);

            // Где лежит файл: для портативной программы это важно видеть.
            var path = new Label();
            path.Name = "lblPath";
            path.AutoSize = false;
            path.AutoEllipsis = true;
            path.UseMnemonic = false;
            path.Font = Ui.SmallFont;
            path.ForeColor = Ui.Muted;
            string pathPrefix = L.T("Файл: ", "File: ");
            int prefixWidth = TextRenderer.MeasureText(pathPrefix, Ui.SmallFont).Width;
            path.Text = pathPrefix + Ui.FitPath(vaultPath, Ui.SmallFont, ContentWidth - prefixWidth);
            path.Height = Ui.SmallFont.Height + Ui.S(2);
            path.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            path.Margin = new Padding(0, Ui.S(14), 0, 0);
            tips.SetToolTip(path, vaultPath);
            Body.Controls.Add(path);

            btnOk = Ui.MakeButton(createMode ? L.T("Создать хранилище", "Create vault") : L.T("Открыть", "Open"));
            btnOk.Name = "btnOk";
            btnOk.Click += OnOk;
            btnCancel = Ui.MakeButton(L.T("Выход", "Exit"));
            btnCancel.Name = "btnCancel";
            btnCancel.DialogResult = DialogResult.Cancel;
            SetButtons(btnOk, btnCancel, false);

            ActiveControl = txtPassword;
            UpdateHint();
        }

        public override bool IsBusy
        {
            get { return busy; }
        }

        /// <summary>true — хранилища ещё нет, окно создаёт новое.</summary>
        public bool CreateMode
        {
            get { return createMode; }
        }

        /// <summary>Забирает открытое хранилище. Дальше за его закрытие отвечает вызывающий.</summary>
        public VaultSession TakeSession()
        {
            VaultSession result = session;
            session = null;
            return result;
        }

        private async void OnOk(object sender, EventArgs e)
        {
            if (busy) return;

            string password = txtPassword.Text;
            if (createMode)
            {
                string problem = MasterPasswordRules.Check(password, txtConfirm.Text);
                if (problem != null)
                {
                    Ui.ShowError(lblError, problem);
                    (password.Length >= MasterPasswordRules.MinLength ? txtConfirm : txtPassword).Focus();
                    return;
                }
            }
            else if (password.Length == 0)
            {
                Ui.ShowError(lblError, L.T("Введите мастер-пароль.", "Enter the master password."));
                txtPassword.Focus();
                return;
            }

            string keyPath = needsKeyFile ? txtKeyFile.Text : null;
            if (needsKeyFile && keyPath.Length == 0)
            {
                Ui.ShowError(lblError, L.T("Это хранилище открывается паролем вместе с ключевым файлом. Укажите файл.",
                                           "This vault is opened with the password together with a key file. Choose the file."));
                btnKeyFile.Focus();
                return;
            }

            SetBusy(true);
            VaultSession opened = null;
            string failure = null;
            try
            {
                // Получение ключа из пароля занимает заметное время — выполняем его не в потоке окна.
                string path = vaultPath;
                bool create = createMode;
                opened = await Task.Run<VaultSession>(delegate
                {
                    if (create) return VaultSession.Create(path, password);
                    byte[] keyFile = keyPath == null ? null : VaultSession.ReadKeyFile(keyPath);
                    return VaultSession.Open(path, password, keyFile);
                });
            }
            catch (VaultException ex)
            {
                failure = ex.Message;
                string backup = VaultSession.BackupPath(vaultPath);
                if (ex.Error == VaultError.BadFormat && File.Exists(backup))
                {
                    // Файл испорчен, но рядом лежит предыдущая сохранённая версия.
                    failure += L.F(" Рядом есть резервная копия: чтобы открыть её, переименуйте «{0}» в «{1}».",
                        " There is a backup copy next to it: to open it, rename “{0}” to “{1}”.",
                        Path.GetFileName(backup), Path.GetFileName(vaultPath));
                }
            }
            catch (CryptographicException ex)
            {
                failure = L.T("Ошибка шифрования. ", "Encryption error. ") + ex.Message;
            }
            catch (IOException ex)
            {
                failure = L.T("Ошибка доступа к файлу. ", "File access error. ") + ex.Message;
            }
            catch (UnauthorizedAccessException ex)
            {
                failure = L.T("Нет доступа к файлу. ", "Access to the file is denied. ") + ex.Message;
            }

            busy = false;
            if (IsDisposed)
            {
                if (opened != null) opened.Dispose();
                return;
            }
            SetBusy(false);

            if (opened == null)
            {
                Ui.ShowError(lblError, failure);
                txtPassword.Focus();
                txtPassword.SelectAll();
                return;
            }

            session = opened;
            if (keyPath != null) LastKeyFile = keyPath;
            txtPassword.Clear();
            if (txtConfirm != null) txtConfirm.Clear();
            DialogResult = DialogResult.OK;
        }

        private void SetBusy(bool value)
        {
            busy = value;
            txtPassword.Enabled = !value;
            if (txtConfirm != null) txtConfirm.Enabled = !value;
            chkShow.Enabled = !value;
            if (btnKeyFile != null) btnKeyFile.Enabled = !value;
            btnOk.Enabled = !value;
            btnCancel.Enabled = !value;
            UseWaitCursor = value;
            if (value)
            {
                Ui.ShowError(lblError, null);
                btnOk.Text = createMode ? L.T("Создание…", "Creating…") : L.T("Проверка…", "Checking…");
            }
            else
            {
                btnOk.Text = createMode ? L.T("Создать хранилище", "Create vault") : L.T("Открыть", "Open");
            }
        }

        private void OnChooseKeyFile(object sender, EventArgs e)
        {
            string path = Ui.PickFile(this, false, L.T("Ключевой файл", "Key file"),
                L.T("Ключевые файлы (*.key)|*.key|Все файлы (*.*)|*.*", "Key files (*.key)|*.key|All files (*.*)|*.*"), null);
            if (path == null) return;
            txtKeyFile.Text = path;
            if (!busy) Ui.ShowError(lblError, null);
        }

        private void OnPasswordChanged(object sender, EventArgs e)
        {
            if (!busy) Ui.ShowError(lblError, null);
            UpdateHint();
        }

        private void UpdateHint()
        {
            if (lblHint == null) return;
            Color color;
            lblHint.Text = MasterPasswordRules.Hint(txtPassword.Text, out color);
            lblHint.ForeColor = color;
        }

        private void OnShowChanged(object sender, EventArgs e)
        {
            bool hide = !chkShow.Checked;
            txtPassword.UseSystemPasswordChar = hide;
            if (txtConfirm != null) txtConfirm.UseSystemPasswordChar = hide;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Пока идёт проверка пароля, окно не закрываем: дождёмся результата.
            if (busy && e.CloseReason == CloseReason.UserClosing)
            {
                e.Cancel = true;
            }
            base.OnFormClosing(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && session != null)
            {
                session.Dispose();
                session = null;
            }
            base.Dispose(disposing);
        }
    }
}
