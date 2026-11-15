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
    /// Защита хранилища: чем оно открывается — одним мастер-паролем или паролем вместе
    /// с ключевым файлом. При сохранении хранилище перешифровывается, а ключ с этого момента
    /// получается функцией Argon2id (так хранилища прежнего формата переводятся на неё).
    /// </summary>
    internal sealed class ProtectionForm : DialogForm
    {
        private readonly VaultSession session;
        private readonly TextBox txtPassword;
        private readonly RadioButton rbNone;
        private readonly RadioButton rbKeep;
        private readonly RadioButton rbNew;
        private readonly RadioButton rbExisting;
        private readonly TextBox txtFile;
        private readonly Button btnBrowse;
        private readonly Label lblError;
        private readonly Button btnOk;
        private readonly Button btnCancel;
        private bool busy;

        public ProtectionForm(VaultSession session)
            : base(L.T("Защита хранилища", "Vault protection"), 520)
        {
            this.session = session;
            Name = "ProtectionForm";

            Body.ColumnCount = 1;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            KdfParameters protection = session.Protection;
            string status = L.F("Сейчас ключ шифрования получается из мастер-пароля функцией {0}.",
                "The encryption key is now derived from the master password with {0}.", protection.Describe());
            status += " " + (protection.KeyFile
                ? L.T("Хранилище открывается паролем вместе с ключевым файлом.", "The vault is opened with the password together with a key file.")
                : L.T("Ключевой файл не используется.", "No key file is used."));
            if (!protection.IsArgon2)
            {
                status += "\n\n" + L.T(
                    "После сохранения хранилище перейдёт на Argon2id: он лучше защищает от подбора пароля на видеокартах. " +
                    "Прежние версии KeyBox (1.x) такое хранилище открыть не смогут.",
                    "After saving, the vault will switch to Argon2id, which protects better against password guessing on graphics cards. " +
                    "Earlier versions of KeyBox (1.x) will not be able to open such a vault.");
            }
            Label lblStatus = Ui.MakeWrapLabel(status, ContentWidth, Ui.TextColor);
            lblStatus.Name = "lblStatus";
            Body.Controls.Add(lblStatus);

            Label passwordLabel = Ui.MakeLabel(L.T("Мастер-пароль", "Master password"));
            passwordLabel.Margin = new Padding(0, Ui.S(16), 0, 0);
            Body.Controls.Add(passwordLabel);

            txtPassword = new TextBox();
            txtPassword.Name = "txtPassword";
            txtPassword.UseSystemPasswordChar = true;
            txtPassword.MaxLength = 1024;
            txtPassword.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtPassword.Margin = new Padding(0, Ui.S(6), 0, 0);
            txtPassword.TextChanged += delegate { if (!busy) Ui.ShowError(lblError, null); };
            Body.Controls.Add(txtPassword);

            Label choiceLabel = Ui.MakeLabel(L.T("Хранилище открывается", "The vault is opened with"));
            choiceLabel.Margin = new Padding(0, Ui.S(16), 0, Ui.S(4));
            Body.Controls.Add(choiceLabel);

            rbNone = MakeRadio("rbNone", L.T("только мастер-паролем", "the master password alone"));
            rbKeep = MakeRadio("rbKeep", L.T("паролем и нынешним ключевым файлом", "the password and the current key file"));
            rbNew = MakeRadio("rbNew", L.T("паролем и новым ключевым файлом — создать его", "the password and a new key file — create it"));
            rbExisting = MakeRadio("rbExisting", L.T("паролем и файлом, который у меня уже есть", "the password and a file I already have"));
            rbKeep.Visible = protection.KeyFile;
            Body.Controls.Add(rbNone);
            Body.Controls.Add(rbKeep);
            Body.Controls.Add(rbNew);
            Body.Controls.Add(rbExisting);

            // Путь к ключевому файлу и кнопка выбора.
            var fileRow = new TableLayoutPanel();
            fileRow.AutoSize = true;
            fileRow.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            fileRow.ColumnCount = 2;
            fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            fileRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            fileRow.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            fileRow.Margin = new Padding(Ui.S(20), Ui.S(6), 0, 0);

            txtFile = new TextBox();
            txtFile.Name = "txtFile";
            txtFile.Font = Ui.Font;
            txtFile.ReadOnly = true;
            txtFile.TabStop = false;
            txtFile.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtFile.Margin = Padding.Empty;

            btnBrowse = Ui.MakeButton(L.T("Выбрать…", "Choose…"));
            btnBrowse.Name = "btnBrowse";
            btnBrowse.MinimumSize = new Size(0, txtFile.PreferredHeight);
            btnBrowse.Margin = new Padding(Ui.S(6), 0, 0, 0);
            btnBrowse.Click += OnBrowse;

            fileRow.Controls.Add(txtFile, 0, 0);
            fileRow.Controls.Add(btnBrowse, 1, 0);
            Body.Controls.Add(fileRow);

            Label warning = Ui.MakeWrapLabel(L.T(
                "Ключевой файл — второй ключ к хранилищу: без него мастер-пароль хранилище не откроет. " +
                "Храните файл отдельно от хранилища и обязательно сделайте его копию: потеряете файл — потеряете доступ к паролям.",
                "A key file is a second key to the vault: without it the master password will not open the vault. " +
                "Keep the file apart from the vault and be sure to make a copy: if the file is lost, so is the access to your passwords."),
                ContentWidth, Ui.Muted);
            warning.Margin = new Padding(0, Ui.S(12), 0, 0);
            Body.Controls.Add(warning);

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(10), 0, 0);
            Body.Controls.Add(lblError);

            btnOk = Ui.MakeButton(L.T("Сохранить", "Save"));
            btnOk.Name = "btnOk";
            btnOk.Click += OnOk;
            btnCancel = Ui.MakeButton(L.T("Отмена", "Cancel"));
            btnCancel.Name = "btnCancel";
            btnCancel.DialogResult = DialogResult.Cancel;
            SetButtons(btnOk, btnCancel, false);

            (protection.KeyFile ? rbKeep : rbNone).Checked = true;
            UpdateFileRow();
            ActiveControl = txtPassword;
        }

        public override bool IsBusy
        {
            get { return busy; }
        }

        private RadioButton MakeRadio(string name, string text)
        {
            var radio = new RadioButton();
            radio.Name = name;
            radio.Text = text;
            radio.AutoSize = true;
            radio.UseMnemonic = false;
            radio.Margin = new Padding(0, Ui.S(2), 0, 0);
            radio.CheckedChanged += delegate
            {
                if (!radio.Checked) return;
                if (txtFile != null) txtFile.Text = "";
                UpdateFileRow();
                if (lblError != null && !busy) Ui.ShowError(lblError, null);
            };
            return radio;
        }

        /// <summary>Путь нужен только для нового или уже имеющегося файла.</summary>
        private void UpdateFileRow()
        {
            if (txtFile == null || btnBrowse == null) return;
            bool needsPath = rbNew.Checked || rbExisting.Checked;
            txtFile.Enabled = needsPath && !busy;
            btnBrowse.Enabled = needsPath && !busy;
        }

        private void OnBrowse(object sender, EventArgs e)
        {
            string filter = L.T("Ключевые файлы (*.key)|*.key|Все файлы (*.*)|*.*", "Key files (*.key)|*.key|All files (*.*)|*.*");
            string path = rbNew.Checked
                ? Ui.PickFile(this, true, L.T("Где сохранить новый ключевой файл", "Where to save the new key file"), filter, "keybox.key")
                : Ui.PickFile(this, false, L.T("Ключевой файл", "Key file"), filter, null);
            if (path == null) return;
            txtFile.Text = path;
            Ui.ShowError(lblError, null);
        }

        private async void OnOk(object sender, EventArgs e)
        {
            if (busy) return;

            string password = txtPassword.Text;
            if (password.Length == 0)
            {
                Fail(L.T("Введите мастер-пароль.", "Enter the master password."), txtPassword);
                return;
            }

            bool create = rbNew.Checked;
            bool useFile = !rbNone.Checked;
            bool needsPath = rbNew.Checked || rbExisting.Checked;
            string path = txtFile.Text;
            if (needsPath && path.Length == 0)
            {
                Fail(create
                    ? L.T("Укажите, куда сохранить новый ключевой файл.", "Choose where to save the new key file.")
                    : L.T("Укажите ключевой файл.", "Choose the key file."), btnBrowse);
                return;
            }
            if (create && string.Equals(Path.GetFullPath(path), Path.GetFullPath(session.FilePath), StringComparison.OrdinalIgnoreCase))
            {
                Fail(L.T("Ключевой файл нельзя сохранить поверх самого хранилища.", "The key file cannot be saved over the vault itself."), btnBrowse);
                return;
            }

            SetBusy(true);
            string failure = null;
            bool wrongPassword = false;
            bool written = false;
            try
            {
                VaultSession target = session;
                wrongPassword = !await Task.Run<bool>(delegate
                {
                    if (!target.VerifyPassword(password)) return false;

                    byte[] keyFile = null;
                    if (create)
                    {
                        // Сначала файл оказывается на диске, и только потом хранилище начинает его требовать.
                        keyFile = VaultFormat.NewKeyFile();
                        File.WriteAllBytes(path, keyFile);
                        written = true;
                        keyFile = VaultSession.ReadKeyFile(path);
                    }
                    else if (needsPath)
                    {
                        keyFile = VaultSession.ReadKeyFile(path);
                    }
                    target.ChangeProtection(password, useFile, keyFile);
                    return true;
                });
            }
            catch (VaultException ex)
            {
                failure = ex.Message;
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
            catch (ObjectDisposedException)
            {
                failure = L.T("Хранилище уже закрыто.", "The vault is already closed.");
            }

            busy = false;
            if (IsDisposed) return;
            SetBusy(false);

            if (failure != null)
            {
                // Новый ключевой файл, который так и не стал ключом, только сбивал бы с толку.
                if (create && written) AtomicFile.TryDelete(path);
                Fail(failure + L.T(" Защита хранилища не изменена.", " The vault protection was not changed."), txtPassword);
                return;
            }
            if (wrongPassword)
            {
                Fail(L.T("Мастер-пароль указан неверно.", "The master password is incorrect."), txtPassword);
                return;
            }

            if (needsPath) UnlockForm.LastKeyFile = path;
            txtPassword.Clear();
            DialogResult = DialogResult.OK;
        }

        private void Fail(string message, Control focus)
        {
            Ui.ShowError(lblError, message);
            focus.Focus();
            var box = focus as TextBox;
            if (box != null) box.SelectAll();
        }

        private void SetBusy(bool value)
        {
            busy = value;
            txtPassword.Enabled = !value;
            rbNone.Enabled = !value;
            rbKeep.Enabled = !value;
            rbNew.Enabled = !value;
            rbExisting.Enabled = !value;
            btnOk.Enabled = !value;
            btnCancel.Enabled = !value;
            UpdateFileRow();
            UseWaitCursor = value;
            btnOk.Text = value ? L.T("Шифрование…", "Encrypting…") : L.T("Сохранить", "Save");
            if (value) Ui.ShowError(lblError, null);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Пока файл перешифровывается, окно не закрываем.
            if (busy) e.Cancel = true;
            base.OnFormClosing(e);
        }
    }
}
