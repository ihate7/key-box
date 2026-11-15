using System;
using System.Collections.Generic;
using System.Windows.Forms;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>
    /// Создание и изменение группы: название и место в дереве — на верхнем уровне
    /// или внутри другой группы. Само хранилище окно не меняет, а только возвращает
    /// введённые значения.
    /// </summary>
    internal sealed class GroupForm : DialogForm
    {
        private sealed class ParentChoice
        {
            public string Id;
            public string Text;

            public override string ToString()
            {
                return Text;
            }
        }

        private readonly VaultData data;
        private readonly Group group;
        private readonly TextBox txtName;
        private readonly ComboBox cmbParent;
        private readonly Label lblError;

        /// <param name="data">Хранилище — из него берётся дерево групп.</param>
        /// <param name="group">Изменяемая группа или null для новой.</param>
        /// <param name="parentId">Где группа находится изначально (null — верхний уровень).</param>
        public GroupForm(VaultData data, Group group, string parentId)
            : base(group == null ? "Новая группа" : "Изменение группы", 440)
        {
            this.data = data;
            this.group = group;
            Name = "GroupForm";

            Body.ColumnCount = 1;
            Body.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100f));

            Body.Controls.Add(Ui.MakeLabel("Название"));

            txtName = new TextBox();
            txtName.Name = "txtName";
            txtName.Text = group == null ? "" : group.Name;
            txtName.MaxLength = VaultData.MaxGroupNameLength;
            txtName.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            txtName.Margin = new Padding(0, Ui.S(6), 0, 0);
            txtName.TextChanged += delegate { Ui.ShowError(lblError, null); };
            Body.Controls.Add(txtName);

            Label parentLabel = Ui.MakeLabel("Находится в");
            parentLabel.Margin = new Padding(0, Ui.S(14), 0, 0);
            Body.Controls.Add(parentLabel);

            // Высота списка задаётся сразу: настоящую он получает только при создании окна,
            // и без этого при крупном масштабе экрана раскладка диалога съезжает.
            cmbParent = new ComboBox();
            cmbParent.Name = "cmbParent";
            cmbParent.DropDownStyle = ComboBoxStyle.DropDownList;
            cmbParent.Font = Ui.Font;
            cmbParent.Height = cmbParent.PreferredHeight;
            cmbParent.MaxDropDownItems = 16;
            cmbParent.Anchor = AnchorStyles.Left | AnchorStyles.Right;
            cmbParent.Margin = new Padding(0, Ui.S(6), 0, 0);
            FillParents(parentId);
            cmbParent.SelectedIndexChanged += delegate { Ui.ShowError(lblError, null); };
            Body.Controls.Add(cmbParent);

            lblError = Ui.MakeErrorLabel(ContentWidth);
            lblError.Margin = new Padding(0, Ui.S(10), 0, 0);
            Body.Controls.Add(lblError);

            Button ok = Ui.MakeButton(group == null ? "Создать" : "Сохранить");
            ok.Name = "btnOk";
            ok.Click += OnOk;
            Button cancel = Ui.MakeButton("Отмена");
            cancel.Name = "btnCancel";
            cancel.DialogResult = DialogResult.Cancel;
            SetButtons(ok, cancel, false);

            ActiveControl = txtName;
            txtName.SelectAll();
        }

        /// <summary>Введённое название без пробелов по краям.</summary>
        public string GroupName
        {
            get { return txtName.Text.Trim(); }
        }

        /// <summary>Выбранная родительская группа; null — верхний уровень.</summary>
        public string ParentId
        {
            get
            {
                var choice = cmbParent.SelectedItem as ParentChoice;
                return choice == null ? null : choice.Id;
            }
        }

        private void FillParents(string selectedId)
        {
            // Группу нельзя вложить в саму себя и в собственные подгруппы — их в списке нет.
            var excluded = new HashSet<string>();
            if (group != null)
            {
                excluded.Add(group.Id);
                foreach (Group descendant in data.DescendantsOf(group.Id)) excluded.Add(descendant.Id);
            }

            var top = new ParentChoice();
            top.Id = null;
            top.Text = "Верхний уровень";
            cmbParent.Items.Add(top);
            cmbParent.SelectedIndex = 0;

            foreach (Group candidate in data.TreeOrder(Ui.CompareNatural))
            {
                if (excluded.Contains(candidate.Id)) continue;

                var choice = new ParentChoice();
                choice.Id = candidate.Id;
                choice.Text = data.GroupPath(candidate.Id);
                cmbParent.Items.Add(choice);
                if (candidate.Id == selectedId)
                {
                    cmbParent.SelectedIndex = cmbParent.Items.Count - 1;
                }
            }
        }

        private void OnOk(object sender, EventArgs e)
        {
            string id = group == null ? null : group.Id;
            string problem = data.ValidateGroupParent(id, ParentId);
            if (problem != null)
            {
                Ui.ShowError(lblError, problem);
                cmbParent.Focus();
                return;
            }

            problem = data.ValidateGroupName(txtName.Text, ParentId, id);
            if (problem != null)
            {
                Ui.ShowError(lblError, problem);
                txtName.Focus();
                txtName.SelectAll();
                return;
            }
            DialogResult = DialogResult.OK;
        }
    }
}
