using System;
using System.Drawing;
using System.Windows.Forms;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>
    /// Прежние пароли записи: посмотреть, скопировать, стереть. Само хранилище окно не меняет:
    /// о просьбе стереть историю оно только сообщает вызывающему.
    /// </summary>
    internal sealed class HistoryForm : DialogForm
    {
        private readonly Entry entry;
        private readonly int clipboardSeconds;
        private readonly string mask = new string((char)0x2022, 8);
        private readonly ListView list;
        private readonly CheckBox chkShow;
        private readonly Button btnCopy;
        private readonly Label lblInfo;

        /// <param name="entry">Запись, чьи прежние пароли показываются.</param>
        /// <param name="title">Название записи для заголовка.</param>
        /// <param name="clipboardSeconds">Через сколько секунд стирать скопированный пароль из буфера обмена.</param>
        public HistoryForm(Entry entry, string title, int clipboardSeconds)
            : base(L.T("Прежние пароли", "Previous passwords"), 520)
        {
            this.entry = entry;
            this.clipboardSeconds = clipboardSeconds;
            Name = "HistoryForm";

            Body.ColumnCount = 1;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            Label caption = Ui.MakeWrapLabel(
                L.F("Запись «{0}». Здесь хранятся пароли, которые были у неё раньше, — на случай, если новый не подошёл.",
                    "Entry “{0}”. The passwords it had before are kept here in case the new one does not work.", title),
                ContentWidth, Ui.TextColor);
            Body.Controls.Add(caption);

            list = new ListView();
            list.Name = "lvHistory";
            list.View = View.Details;
            list.FullRowSelect = true;
            list.HideSelection = false;
            list.MultiSelect = false;
            list.HeaderStyle = ColumnHeaderStyle.Nonclickable;
            list.Font = Ui.Font;
            list.Columns.Add(L.T("Заменён", "Replaced"), Ui.S(150));
            list.Columns.Add(L.T("Пароль", "Password"), ContentWidth - Ui.S(150) - SystemInformation.VerticalScrollBarWidth - Ui.S(6));
            list.Size = new Size(ContentWidth, Ui.S(196));
            list.Margin = new Padding(0, Ui.S(12), 0, 0);
            list.SelectedIndexChanged += delegate { UpdateButtons(); };
            list.ItemActivate += delegate { CopySelected(); };
            Body.Controls.Add(list);

            // Под списком: «показать пароли» слева, действия справа.
            var actions = new TableLayoutPanel();
            actions.AutoSize = true;
            actions.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            actions.ColumnCount = 3;
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            actions.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            actions.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            actions.Margin = new Padding(0, Ui.S(10), 0, 0);

            chkShow = new CheckBox();
            chkShow.Name = "chkShow";
            chkShow.Text = L.T("Показать пароли", "Show passwords");
            chkShow.AutoSize = true;
            chkShow.Anchor = AnchorStyles.Left;
            chkShow.Margin = Padding.Empty;
            chkShow.CheckedChanged += delegate { Fill(); };

            btnCopy = Ui.MakeButton(L.T("Копировать", "Copy"));
            btnCopy.Name = "btnCopy";
            btnCopy.Click += delegate { CopySelected(); };

            Button clear = Ui.MakeButton(L.T("Стереть все…", "Erase all…"));
            clear.Name = "btnClear";
            clear.Click += OnClear;

            actions.Controls.Add(chkShow, 0, 0);
            actions.Controls.Add(btnCopy, 1, 0);
            actions.Controls.Add(clear, 2, 0);
            Body.Controls.Add(actions);

            lblInfo = Ui.MakeWrapLabel("", ContentWidth, Ui.Muted);
            lblInfo.Name = "lblInfo";
            lblInfo.Margin = new Padding(0, Ui.S(8), 0, 0);
            lblInfo.Text = L.F("Хранится не больше {0} последних паролей.", "No more than the last {0} passwords are kept.", VaultData.MaxHistory);
            Body.Controls.Add(lblInfo);

            Button close = Ui.MakeButton(L.T("Закрыть", "Close"));
            close.Name = "btnOk";
            close.DialogResult = DialogResult.OK;
            SetButtons(close, null, false);

            Fill();
            if (list.Items.Count > 0) list.Items[0].Selected = true;
            UpdateButtons();
        }

        /// <summary>true, если пользователь попросил стереть историю и подтвердил это.</summary>
        public bool ClearRequested { get; private set; }

        private void Fill()
        {
            int selected = list.SelectedIndices.Count > 0 ? list.SelectedIndices[0] : -1;
            bool show = chkShow.Checked;

            list.BeginUpdate();
            try
            {
                list.Items.Clear();
                foreach (PasswordRecord record in entry.History)
                {
                    DateTime replaced;
                    string when = VaultData.TryParseTimestamp(record.Replaced, out replaced) ? L.FormatTime(replaced) : "—";
                    var item = new ListViewItem(when);
                    item.UseItemStyleForSubItems = false;
                    ListViewItem.ListViewSubItem password = item.SubItems.Add(show ? record.Password : mask);
                    if (show) password.Font = Ui.MonoFont;
                    else password.ForeColor = Ui.Muted;
                    list.Items.Add(item);
                }
                if (selected >= 0 && selected < list.Items.Count) list.Items[selected].Selected = true;
            }
            finally
            {
                list.EndUpdate();
            }
        }

        private void UpdateButtons()
        {
            btnCopy.Enabled = list.SelectedIndices.Count == 1;
        }

        private void CopySelected()
        {
            if (list.SelectedIndices.Count != 1) return;
            PasswordRecord record = entry.History[list.SelectedIndices[0]];

            bool copied = ClipboardGuard.Copy(record.Password, L.T("Пароль", "Password"), clipboardSeconds);
            lblInfo.ForeColor = copied ? Ui.Success : Ui.Danger;
            lblInfo.Text = copied
                ? L.F("Пароль скопирован. Буфер обмена очистится через {0} с.", "Password copied. The clipboard will be cleared in {0} s.", clipboardSeconds)
                : L.T("Не удалось скопировать: буфер обмена занят другой программой.", "Could not copy: the clipboard is in use by another program.");
        }

        private void OnClear(object sender, EventArgs e)
        {
            bool confirmed = MsgBox.ConfirmDanger(this, Text,
                L.T("Стереть все прежние пароли этой записи?\n\nВосстановить их будет нельзя.",
                    "Erase all previous passwords of this entry?\n\nThey cannot be restored."),
                L.T("Стереть", "Erase"));
            if (!confirmed) return;

            ClearRequested = true;
            DialogResult = DialogResult.OK;
        }
    }
}
