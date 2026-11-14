using System;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Windows.Forms;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>Смена мастер-пароля: текущий пароль, новый и его повтор.</summary>
    internal sealed class ChangePasswordForm : DialogForm
    {
        private readonly VaultSession session;
        private readonly TextBox txtCurrent;
        private readonly TextBox txtNew;
        private readonly TextBox txtConfirm;
        private readonly CheckBox chkShow;
        private readonly Label lblHint;
        private readonly Label lblError;
        private readonly Button btnOk;
        private readonly Button btnCancel;
        private bool busy;

        public ChangePasswordForm(VaultSession session)
            : base("Смена мастер-пароля", 430)
        {
            this.session = session;
            Name = "ChangePasswordForm";

            Body.ColumnCount = 1;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            Body.Controls.Add(Ui.MakeLabel("Текущий мастер-пароль"));
            txtCurrent = MakePasswordBox("txtCurrent");
            Body.Controls.Add(txtCurrent);

            Label newLabel = Ui.MakeLabel("Новый мастер-пароль");
            newLabel.Margin = new Padding(0, Ui.S(14), 0, 0);
            Body.Controls.Add(newLabel);
            txtNew = MakePasswordBox("txtNew");
            txtNew.TextChanged += delegate { UpdateHint(); };
            Body.Controls.Add(txtNew);

            Label confirmLabel = Ui.MakeLabel("Повторите новый пароль");
            confirmLabel.Margin = new Padding(0, Ui.S(12), 0, 0);
            Body.Controls.Add(confirmLabel);
            txtConfirm = MakePasswordBox("txtConfirm");
            Body.Controls.Add(txtConfirm);

            lblHint = Ui.MakeWrapLabel("", ContentWidth, Ui.Muted);
            lblHint.Name = "lblHint";
            lblHint.Margin = new Padding(0, Ui.S(8), 0, 0);
            Body.Controls.Add(lblHint);

            chkShow = new CheckBox();
            chkShow.Name = "chkShow";
            chkShow.Text = "Показать пароли";
            chkShow.AutoSize = true;
            chkShow.Margin = new Padding(0, Ui.S(10), 0, 0);
            chkShow.CheckedChanged += delegate
            {
                bool hide = !chkShow.Checked;
                txtCurrent.UseSystemPasswordChar = hide;
                txtNew.UseSystemPasswordChar = hide;
                txtConfirm.UseSystemPasswordChar = hide;
            };
            Body.Controls.Add(chkShow);

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(10), 0, 0);
            Body.Controls.Add(lblError);

            btnOk = Ui.MakeButton("Сменить пароль");
            btnOk.Name = "btnOk";
            btnOk.Click += OnOk;
            btnCancel = Ui.MakeButton("Отмена");
            btnCancel.Name = "btnCancel";
            btnCancel.DialogResult = DialogResult.Cancel;
            SetButtons(btnOk, btnCancel, false);

            ActiveControl = txtCurrent;
            UpdateHint();
        }

        public override bool IsBusy
        {
            get { return busy; }
        }

        private TextBox MakePasswordBox(string name)
        {
            var box = new TextBox();
            box.Name = name;
            box.UseSystemPasswordChar = true;
            box.MaxLength = 1024;
            box.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            box.Margin = new Padding(0, Ui.S(6), 0, 0);
            box.TextChanged += delegate { if (!busy) Ui.ShowError(lblError, null); };
            return box;
        }

        private async void OnOk(object sender, EventArgs e)
        {
            if (busy) return;

            string current = txtCurrent.Text;
            string replacement = txtNew.Text;

            if (current.Length == 0)
            {
                Fail("Введите текущий мастер-пароль.", txtCurrent);
                return;
            }
            string problem = MasterPasswordRules.Check(replacement, txtConfirm.Text);
            if (problem != null)
            {
                Fail(problem, replacement.Length >= MasterPasswordRules.MinLength ? txtConfirm : txtNew);
                return;
            }
            if (replacement == current)
            {
                Fail("Новый пароль совпадает с текущим.", txtNew);
                return;
            }

            SetBusy(true);
            string failure = null;
            bool wrongCurrent = false;
            try
            {
                VaultSession target = session;
                wrongCurrent = !await Task.Run<bool>(delegate
                {
                    if (!target.VerifyPassword(current)) return false;
                    target.ChangePassword(replacement);
                    return true;
                });
            }
            catch (VaultException ex)
            {
                failure = ex.Message;
            }
            catch (CryptographicException ex)
            {
                failure = "Ошибка шифрования. " + ex.Message;
            }
            catch (IOException ex)
            {
                failure = "Ошибка доступа к файлу. " + ex.Message;
            }
            catch (ObjectDisposedException)
            {
                failure = "Хранилище уже закрыто.";
            }

            busy = false;
            if (IsDisposed) return;
            SetBusy(false);

            if (failure != null)
            {
                Fail(failure + " Мастер-пароль не изменён.", txtNew);
                return;
            }
            if (wrongCurrent)
            {
                Fail("Текущий мастер-пароль указан неверно.", txtCurrent);
                return;
            }

            txtCurrent.Clear();
            txtNew.Clear();
            txtConfirm.Clear();
            DialogResult = DialogResult.OK;
        }

        private void Fail(string message, TextBox focus)
        {
            Ui.ShowError(lblError, message);
            focus.Focus();
            focus.SelectAll();
        }

        private void SetBusy(bool value)
        {
            busy = value;
            txtCurrent.Enabled = !value;
            txtNew.Enabled = !value;
            txtConfirm.Enabled = !value;
            chkShow.Enabled = !value;
            btnOk.Enabled = !value;
            btnCancel.Enabled = !value;
            UseWaitCursor = value;
            btnOk.Text = value ? "Шифрование…" : "Сменить пароль";
            if (value) Ui.ShowError(lblError, null);
        }

        private void UpdateHint()
        {
            Color color;
            lblHint.Text = MasterPasswordRules.Hint(txtNew.Text, out color);
            lblHint.ForeColor = color;
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Пока файл перешифровывается, окно не закрываем.
            if (busy) e.Cancel = true;
            base.OnFormClosing(e);
        }
    }
}
