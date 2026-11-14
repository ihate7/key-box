using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.Windows.Forms;
using Microsoft.Win32;
using KeyBox.Vault;
using FormsTimer = System.Windows.Forms.Timer;

namespace KeyBox.UI
{
    /// <summary>
    /// Главное окно: слева группы, справа записи выбранной группы.
    /// Любое изменение сразу шифруется и записывается в файл — отдельной кнопки «Сохранить» нет.
    /// </summary>
    internal sealed class MainForm : BaseForm
    {
        /// <summary>Через сколько минут бездействия хранилище блокируется само.</summary>
        public const int AutoLockMinutes = 5;

        /// <summary>Через сколько секунд скопированный логин или пароль стирается из буфера обмена.</summary>
        public const int ClipboardClearSeconds = 30;

        private const string DragFormat = "KeyBox.EntryIds";
        private const int ColDescription = 0;
        private const int ColLogin = 1;
        private const int ColPassword = 2;
        private const int ColGroup = 3;

        // Положение окна переживает блокировку, но на диск не записывается:
        // программа не оставляет на компьютере никаких следов.
        private static Rectangle savedBounds;
        private static bool savedMaximized;
        private static bool hasSavedBounds;

        private readonly VaultSession session;
        private readonly IdleMonitor idle = new IdleMonitor();
        private readonly FormsTimer tick = new FormsTimer();
        private readonly string passwordMask = new string((char)0x2022, 8);

        private ToolStrip toolbar;
        private ToolStripButton btnAdd;
        private ToolStripButton btnEdit;
        private ToolStripButton btnDelete;
        private ToolStripButton btnCopyLogin;
        private ToolStripButton btnCopyPassword;
        private ToolStripDropDownButton btnMove;
        private ToolStripButton btnShow;
        private ToolStripButton btnLock;
        private ToolStripDropDownButton btnMore;
        private ToolStripTextBox txtSearch;

        private ToolStrip groupBar;
        private ToolStripButton btnGroupAdd;
        private ToolStripButton btnGroupRename;
        private ToolStripButton btnGroupDelete;
        private GroupListBox lstGroups;

        private Panel entriesPane;
        private EntryListView lvEntries;
        private ColumnHeader colDescription;
        private ColumnHeader colLogin;
        private ColumnHeader colPassword;
        private ColumnHeader colGroup;
        private ImageList rowImages;
        private Bitmap rowSpacer;
        private PassThroughLabel lblEmpty;
        private Bitmap folderIcon;

        private StatusStrip status;
        private ToolStripStatusLabel lblCount;
        private ToolStripStatusLabel lblMessage;
        private ToolStripStatusLabel lblPath;

        private ContextMenuStrip entryMenu;
        private ContextMenuStrip groupMenu;

        private GroupFilter filter = GroupFilter.All;
        private int sortColumn = ColDescription;
        private bool sortAscending = true;
        private bool showPasswords;
        private bool dirty;
        private bool refreshing;
        private bool adjustingColumns;
        private bool suppressSearch;
        private bool closing;
        private bool hadSearch;
        private string flashText = "";
        private int flashSeconds;

        public MainForm(VaultSession session)
        {
            if (session == null) throw new ArgumentNullException("session");
            this.session = session;
            AutoLockSeconds = AutoLockMinutes * 60;

            Name = "MainForm";
            Text = Program.AppName;
            BackColor = SystemColors.Window;
            ForeColor = Ui.TextColor;
            MinimumSize = new Size(Ui.S(780), Ui.S(440));
            ApplySavedBounds();

            BuildToolbar();
            BuildStatusBar();
            Control groupsPane = BuildGroupsPane();
            BuildEntriesPane();
            BuildMenus();

            var splitter = new LineSplitter();
            splitter.Dock = DockStyle.Left;
            splitter.Width = Ui.S(4);
            splitter.MinSize = Ui.S(160);
            splitter.MinExtra = Ui.S(420);
            splitter.BackColor = Ui.PaneBack;

            // Порядок важен: стыкуются от последнего к первому, заполняющая панель — первой.
            Controls.Add(entriesPane);
            Controls.Add(splitter);
            Controls.Add(groupsPane);
            Controls.Add(toolbar);
            Controls.Add(status);

            ClipboardGuard.Changed += OnClipboardChanged;
            SystemEvents.SessionSwitch += OnSessionSwitch;
            SystemEvents.PowerModeChanged += OnPowerModeChanged;
            Application.AddMessageFilter(idle);

            tick.Interval = 1000;
            tick.Tick += OnTick;
            tick.Start();

            RefreshAll();
            UpdateStatus();
            ActiveControl = lvEntries;
        }

        /// <summary>true, если окно закрылось по блокировке: нужно снова спросить мастер-пароль.</summary>
        public bool LockRequested { get; private set; }

        /// <summary>Порог автоблокировки в секундах (отдельным свойством — чтобы его могли менять тесты).</summary>
        internal int AutoLockSeconds { get; set; }

        private VaultData Data
        {
            get { return session.Data; }
        }

        // =====================================================================
        //  Построение окна
        // =====================================================================

        private void BuildToolbar()
        {
            toolbar = new ToolStrip();
            toolbar.Font = Ui.Font;
            toolbar.Name = "toolbar";
            toolbar.GripStyle = ToolStripGripStyle.Hidden;
            toolbar.BackColor = SystemColors.Window;
            toolbar.Tag = FlatRenderer.LineBelow;
            toolbar.Padding = new Padding(Ui.S(8), Ui.S(6), Ui.S(8), Ui.S(7));
            toolbar.ImageScalingSize = new Size(Ui.S(16), Ui.S(16));
            toolbar.Dock = DockStyle.Top;
            toolbar.ShowItemToolTips = true;
            toolbar.TabStop = true;   // до панели можно дойти клавишей Tab — все команды доступны без мыши

            btnAdd = ToolButton("btnAdd", "Добавить", Ui.GlyphAdd, "Новая запись (Ins)", true, delegate { AddEntry(); });
            btnEdit = ToolButton("btnEdit", "Изменить", Ui.GlyphEdit, "Изменить запись (Enter)", true, delegate { EditEntry(); });
            btnDelete = ToolButton("btnDelete", "Удалить", Ui.GlyphDelete, "Удалить выбранные записи (Del)", true, delegate { DeleteEntries(); });
            btnCopyLogin = ToolButton("btnCopyLogin", "Логин", Ui.GlyphCopy, "Копировать логин (Ctrl+B)", true, delegate { CopyField(false); });
            btnCopyPassword = ToolButton("btnCopyPassword", "Пароль", Ui.GlyphCopy, "Копировать пароль (Ctrl+C)", true, delegate { CopyField(true); });

            btnMove = new ToolStripDropDownButton("В группу");
            btnMove.Name = "btnMove";
            StyleToolItem(btnMove, Ui.GlyphMove, "Переместить выбранные записи в другую группу", true);
            btnMove.DropDownItems.Add(new ToolStripMenuItem("…"));
            StyleMenu(btnMove.DropDown);
            btnMove.DropDownOpening += delegate { PopulateMoveMenu(btnMove.DropDownItems); };

            btnShow = ToolButton("btnShow", "Показать пароли", Ui.GlyphEye, "Показать или скрыть пароли в списке (Ctrl+H)", false, delegate { SetShowPasswords(btnShow.Checked); });
            btnShow.CheckOnClick = true;

            // Правый край: поиск, блокировка, прочее. Выровненные вправо элементы
            // добавляются справа налево.
            btnMore = new ToolStripDropDownButton("Ещё");
            btnMore.Name = "btnMore";
            StyleToolItem(btnMore, Ui.GlyphMore, "Смена мастер-пароля, сведения о программе", false);
            btnMore.Alignment = ToolStripItemAlignment.Right;
            btnMore.ShowDropDownArrow = false;
            var miChangePassword = new ToolStripMenuItem("Сменить мастер-пароль…");
            miChangePassword.Name = "miChangePassword";
            miChangePassword.Click += delegate { ChangeMasterPassword(); };
            var miAbout = new ToolStripMenuItem("О программе");
            miAbout.Name = "miAbout";
            miAbout.Click += delegate { ShowAbout(); };
            StyleMenu(btnMore.DropDown);
            btnMore.DropDownItems.Add(miChangePassword);
            btnMore.DropDownItems.Add(new ToolStripSeparator());
            btnMore.DropDownItems.Add(miAbout);

            btnLock = ToolButton("btnLock", "Заблокировать", Ui.GlyphLock, "Заблокировать хранилище (Ctrl+L)", true, delegate { RequestLock(true); });
            btnLock.Alignment = ToolStripItemAlignment.Right;

            txtSearch = new ToolStripTextBox();
            txtSearch.Name = "txtSearch";
            txtSearch.Alignment = ToolStripItemAlignment.Right;
            txtSearch.Font = Ui.Font;
            txtSearch.BorderStyle = BorderStyle.FixedSingle;
            txtSearch.AutoSize = false;
            txtSearch.Size = new Size(Ui.S(200), txtSearch.TextBox.PreferredHeight);
            txtSearch.Margin = new Padding(Ui.S(6), 0, Ui.S(8), 0);
            txtSearch.ToolTipText = "Поиск по описанию, логину и названию группы (Ctrl+F)";
            txtSearch.AccessibleName = "Поиск";
            txtSearch.TextChanged += OnSearchChanged;
            txtSearch.TextBox.HandleCreated += delegate
            {
                NativeMethods.SendMessage(txtSearch.TextBox.Handle, NativeMethods.EM_SETCUEBANNER, (IntPtr)1, "Поиск");
            };

            toolbar.Items.AddRange(new ToolStripItem[]
            {
                btnAdd, btnEdit, btnDelete, new ToolStripSeparator(),
                btnCopyLogin, btnCopyPassword, new ToolStripSeparator(),
                btnMove, new ToolStripSeparator(),
                btnShow,
                btnMore, btnLock, txtSearch
            });
        }

        private ToolStripButton ToolButton(string name, string text, int glyph, string tip, bool showText, EventHandler onClick)
        {
            var button = new ToolStripButton(text);
            button.Name = name;
            StyleToolItem(button, glyph, tip, showText);
            button.Click += onClick;
            return button;
        }

        private static void StyleToolItem(ToolStripItem item, int glyph, string tip, bool showText)
        {
            Bitmap image = Ui.Glyph(glyph, 16, Ui.GlyphColor);
            item.Image = image;
            if (image == null)
            {
                item.DisplayStyle = ToolStripItemDisplayStyle.Text;
            }
            else
            {
                item.DisplayStyle = showText ? ToolStripItemDisplayStyle.ImageAndText : ToolStripItemDisplayStyle.Image;
            }
            item.AutoToolTip = false;
            item.ToolTipText = tip;
            item.AccessibleName = item.Text;
            item.Padding = new Padding(Ui.S(4), Ui.S(3), Ui.S(4), Ui.S(3));
            item.Margin = new Padding(0, 0, Ui.S(2), 0);
        }

        private void BuildStatusBar()
        {
            status = new StatusStrip();
            status.Font = Ui.Font;
            status.Name = "status";
            status.BackColor = SystemColors.Control;
            status.SizingGrip = true;
            status.ShowItemToolTips = true;

            lblCount = new ToolStripStatusLabel();
            lblCount.Name = "lblCount";

            lblMessage = new ToolStripStatusLabel();
            lblMessage.Name = "lblMessage";
            lblMessage.Spring = true;
            lblMessage.TextAlign = ContentAlignment.MiddleLeft;

            lblPath = new ToolStripStatusLabel();
            lblPath.Name = "lblPath";
            lblPath.ForeColor = Ui.Muted;
            lblPath.Text = Ui.FitPath(session.FilePath, Ui.Font, Ui.S(400));
            lblPath.ToolTipText = "Файл хранилища: " + session.FilePath;

            status.Items.AddRange(new ToolStripItem[] { lblCount, lblMessage, lblPath });
        }

        private Control BuildGroupsPane()
        {
            var pane = new Panel();
            pane.Name = "groupsPane";
            pane.Dock = DockStyle.Left;
            pane.Width = Ui.S(232);
            pane.BackColor = Ui.PaneBack;

            groupBar = new ToolStrip();
            groupBar.Font = Ui.Font;
            groupBar.Name = "groupBar";
            groupBar.GripStyle = ToolStripGripStyle.Hidden;
            groupBar.BackColor = Ui.PaneBack;
            groupBar.Dock = DockStyle.Top;
            groupBar.Padding = new Padding(Ui.S(12), Ui.S(8), Ui.S(6), Ui.S(4));
            groupBar.ImageScalingSize = new Size(Ui.S(16), Ui.S(16));
            groupBar.ShowItemToolTips = true;
            groupBar.CanOverflow = false;

            var caption = new ToolStripLabel("Группы");
            caption.Font = Ui.BoldFont;
            caption.ForeColor = Ui.TextColor;

            btnGroupDelete = ToolButton("btnGroupDelete", "Удалить группу", Ui.GlyphDelete, "Удалить группу (Del)", false, delegate { DeleteGroup(); });
            btnGroupRename = ToolButton("btnGroupRename", "Переименовать группу", Ui.GlyphRename, "Переименовать группу (F2)", false, delegate { RenameGroup(); });
            btnGroupAdd = ToolButton("btnGroupAdd", "Новая группа", Ui.GlyphAdd, "Новая группа (Ctrl+G)", false, delegate { AddGroup(); });
            btnGroupDelete.Alignment = ToolStripItemAlignment.Right;
            btnGroupRename.Alignment = ToolStripItemAlignment.Right;
            btnGroupAdd.Alignment = ToolStripItemAlignment.Right;

            groupBar.Items.AddRange(new ToolStripItem[] { caption, btnGroupDelete, btnGroupRename, btnGroupAdd });

            lstGroups = new GroupListBox();
            lstGroups.Name = "lstGroups";
            lstGroups.Dock = DockStyle.Fill;
            lstGroups.AllowDrop = true;
            lstGroups.AccessibleName = "Группы";
            lstGroups.SelectedIndexChanged += OnGroupSelected;
            lstGroups.MouseDown += OnGroupsMouseDown;
            lstGroups.KeyDown += OnGroupsKeyDown;
            lstGroups.DragOver += OnGroupsDragOver;
            lstGroups.DragLeave += delegate { lstGroups.DropIndex = -1; };
            lstGroups.DragDrop += OnGroupsDragDrop;

            pane.Controls.Add(lstGroups);
            pane.Controls.Add(groupBar);
            return pane;
        }

        private void BuildEntriesPane()
        {
            entriesPane = new Panel();
            entriesPane.Name = "entriesPane";
            entriesPane.Dock = DockStyle.Fill;
            entriesPane.BackColor = SystemColors.Window;

            lvEntries = new EntryListView();
            lvEntries.Name = "lvEntries";
            lvEntries.Dock = DockStyle.Fill;
            lvEntries.AccessibleName = "Записи";
            colDescription = lvEntries.Columns.Add("Описание", Ui.S(300));
            colLogin = lvEntries.Columns.Add("Логин", Ui.S(210));
            colPassword = lvEntries.Columns.Add("Пароль", Ui.S(130));
            colGroup = lvEntries.Columns.Add("Группа", Ui.S(150));

            // Высота строки в стандартном списке задаётся только высотой значка, поэтому
            // подкладываем прозрачный значок шириной в один пиксель — строки становятся просторнее.
            rowImages = new ImageList();
            rowImages.ColorDepth = ColorDepth.Depth32Bit;
            rowImages.ImageSize = new Size(1, Ui.S(26));
            rowSpacer = new Bitmap(1, Ui.S(26), PixelFormat.Format32bppArgb);
            rowImages.Images.Add(rowSpacer);
            lvEntries.SmallImageList = rowImages;

            lvEntries.SelectedIndexChanged += delegate { if (!refreshing) UpdateCommands(); };
            lvEntries.ItemActivate += delegate { EditEntry(); };
            lvEntries.ColumnClick += OnColumnClick;
            lvEntries.KeyDown += OnEntriesKeyDown;
            lvEntries.ItemDrag += OnEntriesItemDrag;
            lvEntries.ClientSizeChanged += delegate { AdjustColumns(); };
            lvEntries.ColumnWidthChanged += delegate { AdjustColumns(); };

            lblEmpty = new PassThroughLabel();
            lblEmpty.Name = "lblEmpty";
            lblEmpty.AutoSize = false;
            lblEmpty.UseMnemonic = false;
            lblEmpty.TextAlign = ContentAlignment.TopCenter;
            lblEmpty.Padding = new Padding(Ui.S(24), Ui.S(64), Ui.S(24), 0);
            lblEmpty.ForeColor = Ui.Muted;
            lblEmpty.BackColor = SystemColors.Window;
            lblEmpty.Visible = false;

            entriesPane.Controls.Add(lblEmpty);
            entriesPane.Controls.Add(lvEntries);
            entriesPane.Resize += delegate { PlaceEmptyLabel(); };

            folderIcon = Ui.Glyph(Ui.GlyphFolder, 16, Ui.GlyphColor);
        }

        private void BuildMenus()
        {
            entryMenu = new ContextMenuStrip();
            StyleMenu(entryMenu);
            entryMenu.Name = "entryMenu";

            ToolStripMenuItem miCopyPassword = MenuItem("Копировать пароль", "Ctrl+C", delegate { CopyField(true); });
            ToolStripMenuItem miCopyLogin = MenuItem("Копировать логин", "Ctrl+B", delegate { CopyField(false); });
            ToolStripMenuItem miEdit = MenuItem("Изменить…", "Enter", delegate { EditEntry(); });
            var miMove = new ToolStripMenuItem("Переместить в группу");
            miMove.DropDownItems.Add(new ToolStripMenuItem("…"));
            StyleMenu(miMove.DropDown);
            miMove.DropDownOpening += delegate { PopulateMoveMenu(miMove.DropDownItems); };
            ToolStripMenuItem miDelete = MenuItem("Удалить", "Del", delegate { DeleteEntries(); });
            ToolStripMenuItem miAdd = MenuItem("Новая запись…", "Ins", delegate { AddEntry(); });

            entryMenu.Items.AddRange(new ToolStripItem[]
            {
                miCopyPassword, miCopyLogin, new ToolStripSeparator(),
                miEdit, miMove, miDelete, new ToolStripSeparator(),
                miAdd
            });
            entryMenu.Opening += delegate
            {
                int selected = lvEntries.SelectedItems.Count;
                miCopyPassword.Enabled = selected == 1;
                miCopyLogin.Enabled = selected == 1;
                miEdit.Enabled = selected == 1;
                miMove.Enabled = selected > 0;
                miDelete.Enabled = selected > 0;
            };
            lvEntries.ContextMenuStrip = entryMenu;

            groupMenu = new ContextMenuStrip();
            StyleMenu(groupMenu);
            groupMenu.Name = "groupMenu";
            ToolStripMenuItem miGroupAdd = MenuItem("Новая группа…", "Ctrl+G", delegate { AddGroup(); });
            ToolStripMenuItem miGroupRename = MenuItem("Переименовать…", "F2", delegate { RenameGroup(); });
            ToolStripMenuItem miGroupDelete = MenuItem("Удалить группу", "Del", delegate { DeleteGroup(); });
            groupMenu.Items.AddRange(new ToolStripItem[] { miGroupAdd, new ToolStripSeparator(), miGroupRename, miGroupDelete });
            groupMenu.Opening += delegate
            {
                bool isGroup = SelectedGroup() != null;
                miGroupRename.Enabled = isGroup;
                miGroupDelete.Enabled = isGroup;
            };
            lstGroups.ContextMenuStrip = groupMenu;
        }

        /// <summary>Шрифт и размер значков в меню — как во всём окне, при любом масштабе экрана.</summary>
        private static void StyleMenu(ToolStripDropDown menu)
        {
            menu.Font = Ui.Font;
            menu.ImageScalingSize = new Size(Ui.S(16), Ui.S(16));
        }

        private static ToolStripMenuItem MenuItem(string text, string keys, EventHandler onClick)
        {
            var item = new ToolStripMenuItem(text);
            item.ShortcutKeyDisplayString = keys;
            item.Click += onClick;
            return item;
        }

        // =====================================================================
        //  Обновление содержимого
        // =====================================================================

        private void RefreshAll()
        {
            RefreshGroups();
            RefreshEntries();
        }

        private List<Group> SortedGroups()
        {
            var groups = new List<Group>(Data.Groups);
            groups.Sort(delegate(Group a, Group b) { return Ui.CompareNatural(a.Name, b.Name); });
            return groups;
        }

        private void RefreshGroups()
        {
            if (filter.Kind == FilterKind.Group && Data.FindGroup(filter.GroupId) == null)
            {
                filter = GroupFilter.All;
            }

            int ungrouped;
            Dictionary<string, int> counts = Data.CountByGroup(out ungrouped);

            refreshing = true;
            lstGroups.BeginUpdate();
            try
            {
                lstGroups.Items.Clear();
                lstGroups.Items.Add(MakeGroupItem(FilterKind.All, null, "Все записи", Data.Entries.Count));
                foreach (Group group in SortedGroups())
                {
                    lstGroups.Items.Add(MakeGroupItem(FilterKind.Group, group.Id, group.Name, counts[group.Id]));
                }
                lstGroups.Items.Add(MakeGroupItem(FilterKind.Ungrouped, null, "Без группы", ungrouped));

                for (int i = 0; i < lstGroups.Items.Count; i++)
                {
                    if (((GroupItem)lstGroups.Items[i]).ToFilter().SameAs(filter))
                    {
                        lstGroups.SelectedIndex = i;
                        break;
                    }
                }
            }
            finally
            {
                lstGroups.EndUpdate();
                refreshing = false;
            }
            UpdateCommands();
        }

        private static GroupItem MakeGroupItem(FilterKind kind, string id, string name, int count)
        {
            var item = new GroupItem();
            item.Kind = kind;
            item.Id = id;
            item.Name = name;
            item.Count = count;
            return item;
        }

        private void RefreshEntries()
        {
            var selected = new HashSet<string>(SelectedIds());
            string focusedId = lvEntries.FocusedItem == null ? null : (string)lvEntries.FocusedItem.Tag;

            var groupNames = new Dictionary<string, string>();
            foreach (Group group in Data.Groups)
            {
                groupNames[group.Id] = group.Name;
            }

            List<Entry> entries = Data.Query(filter, txtSearch.Text);
            SortEntries(entries, groupNames);

            var items = new ListViewItem[entries.Count];
            for (int i = 0; i < items.Length; i++)
            {
                items[i] = MakeItem(entries[i], groupNames);
            }

            refreshing = true;
            lvEntries.BeginUpdate();
            try
            {
                lvEntries.Items.Clear();
                lvEntries.Items.AddRange(items);

                ListViewItem firstSelected = null;
                foreach (ListViewItem item in items)
                {
                    string id = (string)item.Tag;
                    if (selected.Contains(id))
                    {
                        item.Selected = true;
                        if (firstSelected == null) firstSelected = item;
                    }
                    if (id == focusedId) item.Focused = true;
                }
                if (firstSelected != null) firstSelected.EnsureVisible();
            }
            finally
            {
                lvEntries.EndUpdate();
                refreshing = false;
            }

            lvEntries.SetSortArrow(sortColumn, sortAscending);
            AdjustColumns();
            UpdateEmptyState(entries.Count);
            UpdateCount(entries.Count);
            UpdateCommands();
        }

        private ListViewItem MakeItem(Entry entry, Dictionary<string, string> groupNames)
        {
            var item = new ListViewItem(Ui.SingleLine(entry.Description));
            item.Tag = entry.Id;
            item.ImageIndex = 0;
            item.UseItemStyleForSubItems = false;

            item.SubItems.Add(entry.Login);

            string passwordText = entry.Password.Length == 0 ? "" : (showPasswords ? entry.Password : passwordMask);
            ListViewItem.ListViewSubItem password = item.SubItems.Add(passwordText);
            if (showPasswords)
            {
                password.Font = Ui.MonoFont;
            }
            else
            {
                password.ForeColor = Ui.Muted;
            }

            string groupName = null;
            if (!string.IsNullOrEmpty(entry.GroupId))
            {
                groupNames.TryGetValue(entry.GroupId, out groupName);
            }
            ListViewItem.ListViewSubItem group = item.SubItems.Add(groupName ?? "");
            group.ForeColor = Ui.Muted;
            return item;
        }

        private void SortEntries(List<Entry> entries, Dictionary<string, string> groupNames)
        {
            int column = sortColumn;
            int direction = sortAscending ? 1 : -1;

            entries.Sort(delegate(Entry a, Entry b)
            {
                int result;
                if (column == ColLogin)
                {
                    result = Ui.CompareNatural(a.Login, b.Login);
                }
                else if (column == ColGroup)
                {
                    result = Ui.CompareNatural(NameOf(groupNames, a.GroupId), NameOf(groupNames, b.GroupId));
                }
                else
                {
                    result = Ui.CompareNatural(a.Description, b.Description);
                }

                // При равенстве — по описанию, затем по логину; порядок всегда однозначный.
                if (result == 0 && column != ColDescription) result = Ui.CompareNatural(a.Description, b.Description);
                if (result == 0 && column != ColLogin) result = Ui.CompareNatural(a.Login, b.Login);
                if (result == 0) return string.CompareOrdinal(a.Id, b.Id);
                return result * direction;
            });
        }

        private static string NameOf(Dictionary<string, string> groupNames, string groupId)
        {
            string name;
            if (!string.IsNullOrEmpty(groupId) && groupNames.TryGetValue(groupId, out name)) return name;
            return "";
        }

        private void AdjustColumns()
        {
            if (adjustingColumns || colDescription == null || !lvEntries.IsHandleCreated) return;
            adjustingColumns = true;
            try
            {
                // Столбец «Описание» занимает всё место, оставшееся от остальных.
                int others = colLogin.Width + colPassword.Width + colGroup.Width;
                int width = Math.Max(Ui.S(180), lvEntries.ClientSize.Width - others);
                if (colDescription.Width != width) colDescription.Width = width;
            }
            finally
            {
                adjustingColumns = false;
            }
        }

        private void UpdateEmptyState(int shown)
        {
            if (shown > 0)
            {
                lblEmpty.Visible = false;
                return;
            }

            string text;
            if (Data.Entries.Count == 0)
            {
                text = "Здесь пока пусто.\nНажмите «Добавить», чтобы создать первую запись.";
            }
            else if (txtSearch.Text.Trim().Length > 0)
            {
                text = "Ничего не найдено.";
            }
            else if (filter.Kind == FilterKind.Ungrouped)
            {
                text = "Записей без группы нет.";
            }
            else
            {
                text = "В этой группе пока нет записей.\nПеретащите записи на группу в списке слева или нажмите «Добавить».";
            }
            lblEmpty.Text = text;
            PlaceEmptyLabel();
            lblEmpty.Visible = true;
            lblEmpty.BringToFront();
        }

        private void PlaceEmptyLabel()
        {
            if (lblEmpty == null || entriesPane == null) return;
            // Подсказка закрывает всю область списка под заголовками столбцов.
            int top = lvEntries.HeaderHeight;
            if (top <= 0) top = Ui.Font.Height + Ui.S(10);
            Size area = entriesPane.ClientSize;
            lblEmpty.SetBounds(0, top, area.Width, Math.Max(0, area.Height - top));
        }

        private void UpdateCount(int shown)
        {
            int total = Data.Entries.Count;
            lblCount.Text = shown == total
                ? "Записей: " + total
                : string.Format("Показано: {0} из {1}", shown, total);
        }

        private void UpdateCommands()
        {
            int selected = lvEntries.SelectedItems.Count;
            btnEdit.Enabled = selected == 1;
            btnDelete.Enabled = selected > 0;
            btnCopyLogin.Enabled = selected == 1;
            btnCopyPassword.Enabled = selected == 1;
            btnMove.Enabled = selected > 0;

            bool isGroup = filter.Kind == FilterKind.Group;
            btnGroupRename.Enabled = isGroup;
            btnGroupDelete.Enabled = isGroup;
        }

        private string[] SelectedIds()
        {
            var ids = new string[lvEntries.SelectedItems.Count];
            for (int i = 0; i < ids.Length; i++)
            {
                ids[i] = (string)lvEntries.SelectedItems[i].Tag;
            }
            return ids;
        }

        private void SelectEntry(string id)
        {
            refreshing = true;
            try
            {
                lvEntries.SelectedItems.Clear();
                foreach (ListViewItem item in lvEntries.Items)
                {
                    if ((string)item.Tag == id)
                    {
                        item.Selected = true;
                        item.Focused = true;
                        item.EnsureVisible();
                        break;
                    }
                }
            }
            finally
            {
                refreshing = false;
            }
            UpdateCommands();
        }

        private Group SelectedGroup()
        {
            return filter.Kind == FilterKind.Group ? Data.FindGroup(filter.GroupId) : null;
        }

        private void SetSearchSilently(string text)
        {
            suppressSearch = true;
            try
            {
                txtSearch.Text = text;
            }
            finally
            {
                suppressSearch = false;
            }
            hadSearch = text.Trim().Length > 0;
        }

        /// <summary>Делает запись видимой в списке (меняя группу и сбрасывая поиск, если нужно) и выделяет её.</summary>
        private void RevealEntry(Entry entry)
        {
            if (txtSearch.Text.Trim().Length > 0 && !Data.Query(GroupFilter.All, txtSearch.Text).Contains(entry))
            {
                SetSearchSilently("");
            }
            if (!filter.Matches(entry))
            {
                filter = GroupFilter.ForEntryGroup(entry.GroupId);
            }
            RefreshAll();
            SelectEntry(entry.Id);
        }

        // =====================================================================
        //  Строка состояния
        // =====================================================================

        private void Flash(string text)
        {
            flashText = text;
            flashSeconds = 5;
            UpdateStatus();
        }

        private void UpdateStatus()
        {
            string text;
            Color color = SystemColors.ControlText;
            if (dirty)
            {
                text = "Внимание: последние изменения не записаны в файл";
                color = Ui.Danger;
            }
            else if (flashSeconds > 0)
            {
                text = flashText;
            }
            else if (ClipboardGuard.Pending)
            {
                text = string.Format("{0} скопирован. Буфер обмена очистится через {1} с",
                    ClipboardGuard.Label, ClipboardGuard.SecondsLeft);
            }
            else
            {
                text = "";
            }
            lblMessage.Text = text;
            lblMessage.ForeColor = color;
        }

        private void OnClipboardChanged(object sender, ClipboardEventArgs e)
        {
            if (closing || IsDisposed) return;
            if (e.Kind == ClipboardEvent.Cleared)
            {
                Flash("Буфер обмена очищен");
                return;
            }
            if (e.Kind == ClipboardEvent.Copied) flashSeconds = 0;
            UpdateStatus();
        }

        private void OnTick(object sender, EventArgs e)
        {
            if (flashSeconds > 0)
            {
                flashSeconds--;
                if (flashSeconds == 0) UpdateStatus();
            }
            if (idle.IdleSeconds >= AutoLockSeconds)
            {
                RequestLock(false);
            }
        }

        // =====================================================================
        //  Сохранение
        // =====================================================================

        /// <summary>
        /// Записывает хранилище в файл. При неудаче предлагает повторить; пока запись
        /// не удалась, изменения остаются в памяти, а в строке состояния висит предупреждение.
        /// </summary>
        private bool SaveVault()
        {
            while (true)
            {
                string problem;
                try
                {
                    session.Save();
                    SetDirty(false);
                    return true;
                }
                catch (VaultException ex) { problem = ex.Message; }
                catch (System.Security.Cryptography.CryptographicException ex) { problem = ex.Message; }
                catch (ObjectDisposedException) { return false; }

                SetDirty(true);
                bool retry = MsgBox.Retry(this, "Не удалось сохранить",
                    problem + "\n\nИзменения пока остаются только в памяти программы. " +
                    "Проверьте, что носитель на месте и доступен для записи, и повторите попытку.");
                if (!retry || closing || LockRequested) return false;
            }
        }

        /// <summary>Запись без диалогов — для автоблокировки. Возвращает false, если не удалось.</summary>
        private bool TrySaveQuietly()
        {
            try
            {
                session.Save();
                SetDirty(false);
                return true;
            }
            catch (VaultException) { return false; }
            catch (System.Security.Cryptography.CryptographicException) { return false; }
            catch (ObjectDisposedException) { return false; }
        }

        private void SetDirty(bool value)
        {
            if (dirty == value) return;
            dirty = value;
            UpdateStatus();
        }

        // =====================================================================
        //  Действия с записями
        // =====================================================================

        internal void AddEntry()
        {
            string groupId = filter.Kind == FilterKind.Group ? filter.GroupId : null;
            using (var dialog = new EntryForm(Data, null, groupId))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK || LockRequested) return;

                Entry entry;
                try
                {
                    entry = Data.AddEntry(dialog.GroupId, dialog.Login, dialog.Password, dialog.Description);
                }
                catch (ValidationException ex)
                {
                    MsgBox.Error(this, "Новая запись", ex.Message);
                    return;
                }
                SaveVault();
                RevealEntry(entry);
                Flash("Запись добавлена");
            }
        }

        internal void EditEntry()
        {
            string[] ids = SelectedIds();
            if (ids.Length != 1) return;
            Entry entry = Data.FindEntry(ids[0]);
            if (entry == null) return;

            using (var dialog = new EntryForm(Data, entry, entry.GroupId))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK || LockRequested) return;

                bool changed;
                try
                {
                    changed = Data.UpdateEntry(entry.Id, dialog.GroupId, dialog.Login, dialog.Password, dialog.Description);
                }
                catch (ValidationException ex)
                {
                    MsgBox.Error(this, "Изменение записи", ex.Message);
                    RefreshAll();
                    return;
                }
                if (!changed) return;

                SaveVault();
                RevealEntry(entry);
                Flash("Запись сохранена");
            }
        }

        internal void DeleteEntries()
        {
            string[] ids = SelectedIds();
            if (ids.Length == 0) return;

            string question;
            if (ids.Length == 1)
            {
                Entry entry = Data.FindEntry(ids[0]);
                question = "Удалить запись «" + TitleOf(entry) + "»?\n\nВосстановить её будет нельзя.";
            }
            else
            {
                question = "Удалить " + Ui.Plural(ids.Length, "выбранную запись", "выбранные записи", "выбранных записей") +
                           "?\n\nВосстановить их будет нельзя.";
            }
            if (!MsgBox.ConfirmDanger(this, "Удаление", question, "Удалить") || LockRequested) return;

            int removed = Data.DeleteEntries(ids);
            SaveVault();
            RefreshAll();
            Flash("Удалено: " + Ui.Plural(removed, "запись", "записи", "записей"));
        }

        private static string TitleOf(Entry entry)
        {
            if (entry == null) return "";
            string title = Ui.SingleLine(entry.Description).Trim();
            if (title.Length == 0) title = entry.Login;
            return Ui.Shorten(title, 60);
        }

        internal void CopyField(bool password)
        {
            string[] ids = SelectedIds();
            if (ids.Length != 1) return;
            Entry entry = Data.FindEntry(ids[0]);
            if (entry == null) return;

            string what = password ? "Пароль" : "Логин";
            string value = password ? entry.Password : entry.Login;
            if (string.IsNullOrEmpty(value))
            {
                Flash(what + " у этой записи не задан");
                return;
            }
            if (!ClipboardGuard.Copy(value, what, ClipboardClearSeconds))
            {
                Flash("Не удалось скопировать: буфер обмена занят другой программой");
            }
        }

        private void MoveEntries(string[] ids, string groupId)
        {
            if (ids == null || ids.Length == 0) return;

            int moved;
            try
            {
                moved = Data.MoveEntries(ids, groupId);
            }
            catch (ValidationException ex)
            {
                MsgBox.Error(this, "Перемещение", ex.Message);
                RefreshAll();
                return;
            }

            if (moved == 0)
            {
                Flash(groupId == null ? "Эти записи и так без группы" : "Записи уже в этой группе");
                return;
            }
            SaveVault();
            RefreshAll();

            string target = groupId == null ? "в «Без группы»" : "в группу «" + Ui.Shorten(Data.GroupName(groupId), 40) + "»";
            Flash("Перемещено " + target + ": " + Ui.Plural(moved, "запись", "записи", "записей"));
        }

        private void MoveSelectedToNewGroup()
        {
            string[] ids = SelectedIds();
            if (ids.Length == 0) return;
            Group group = PromptNewGroup();
            if (group == null) return;
            // Группа уже создана; MoveEntries сохранит её вместе с перемещением.
            MoveEntries(ids, group.Id);
        }

        /// <summary>Заполняет меню «переместить в группу» — и для кнопки на панели, и для контекстного меню.</summary>
        private void PopulateMoveMenu(ToolStripItemCollection items)
        {
            var old = new ToolStripItem[items.Count];
            items.CopyTo(old, 0);
            items.Clear();
            foreach (ToolStripItem item in old)
            {
                item.Dispose();
            }

            // Если все выбранные записи лежат в одной группе, этот пункт недоступен.
            string[] ids = SelectedIds();
            string common = null;
            bool sameGroup = ids.Length > 0;
            for (int i = 0; i < ids.Length; i++)
            {
                Entry entry = Data.FindEntry(ids[i]);
                string groupId = entry == null ? "" : (entry.GroupId ?? "");
                if (i == 0) common = groupId;
                else if (common != groupId) sameGroup = false;
            }

            List<Group> groups = SortedGroups();
            foreach (Group group in groups)
            {
                string targetId = group.Id;
                var item = new ToolStripMenuItem(Ui.MenuText(group.Name));
                item.Image = folderIcon;
                item.Enabled = !(sameGroup && common == targetId);
                item.Click += delegate { MoveEntries(SelectedIds(), targetId); };
                items.Add(item);
            }
            if (groups.Count > 0) items.Add(new ToolStripSeparator());

            var none = new ToolStripMenuItem("Без группы");
            none.Enabled = !(sameGroup && common == "");
            none.Click += delegate { MoveEntries(SelectedIds(), null); };
            items.Add(none);

            items.Add(new ToolStripSeparator());
            var create = new ToolStripMenuItem("Новая группа…");
            create.Click += delegate { MoveSelectedToNewGroup(); };
            items.Add(create);
        }

        internal void SetShowPasswords(bool value)
        {
            showPasswords = value;
            if (btnShow.Checked != value) btnShow.Checked = value;
            RefreshEntries();
        }

        // =====================================================================
        //  Действия с группами
        // =====================================================================

        private Group PromptNewGroup()
        {
            string name = InputBox.Ask(this, "Новая группа", "Название группы", "", "Создать",
                VaultData.MaxGroupNameLength,
                delegate(string value) { return Data.ValidateGroupName(value, null); });
            if (name == null || LockRequested) return null;

            try
            {
                return Data.AddGroup(name);
            }
            catch (ValidationException ex)
            {
                MsgBox.Error(this, "Новая группа", ex.Message);
                return null;
            }
        }

        internal void AddGroup()
        {
            Group group = PromptNewGroup();
            if (group == null) return;

            SaveVault();
            SetSearchSilently("");
            filter = GroupFilter.ForGroup(group.Id);
            RefreshAll();
            Flash("Группа «" + Ui.Shorten(group.Name, 40) + "» создана");
        }

        internal void RenameGroup()
        {
            Group group = SelectedGroup();
            if (group == null) return;

            string groupId = group.Id;
            string name = InputBox.Ask(this, "Переименование группы", "Название группы", group.Name, "Переименовать",
                VaultData.MaxGroupNameLength,
                delegate(string value) { return Data.ValidateGroupName(value, groupId); });
            if (name == null || LockRequested || name == group.Name) return;

            try
            {
                Data.RenameGroup(groupId, name);
            }
            catch (ValidationException ex)
            {
                MsgBox.Error(this, "Переименование группы", ex.Message);
                RefreshAll();
                return;
            }
            SaveVault();
            RefreshAll();
            Flash("Группа переименована");
        }

        internal void DeleteGroup()
        {
            Group group = SelectedGroup();
            if (group == null) return;

            int inside = Data.Query(GroupFilter.ForGroup(group.Id), null).Count;
            string question = "Удалить группу «" + Ui.Shorten(group.Name, 60) + "»?";
            if (inside > 0)
            {
                question += "\n\nЗаписи при этом не удаляются: " +
                            Ui.Plural(inside, "запись", "записи", "записей") +
                            " из этой группы " + (inside == 1 ? "останется" : "останутся") + " в разделе «Без группы».";
            }
            if (!MsgBox.ConfirmDanger(this, "Удаление группы", question, "Удалить группу") || LockRequested) return;

            try
            {
                Data.DeleteGroup(group.Id);
            }
            catch (ValidationException ex)
            {
                MsgBox.Error(this, "Удаление группы", ex.Message);
                RefreshAll();
                return;
            }
            SaveVault();
            filter = inside > 0 ? GroupFilter.Ungrouped : GroupFilter.All;
            RefreshAll();
            Flash("Группа удалена");
        }

        // =====================================================================
        //  Блокировка, мастер-пароль, сведения
        // =====================================================================

        /// <summary>
        /// Блокирует хранилище: окно закрывается, расшифрованные данные и ключ выбрасываются
        /// из памяти, программа снова спрашивает мастер-пароль.
        /// </summary>
        /// <param name="byUser">true — по команде пользователя, false — автоматически.</param>
        internal void RequestLock(bool byUser)
        {
            if (LockRequested || closing) return;

            // Пока диалог перешифровывает файл, блокировку откладываем до следующей проверки.
            if (HasBusyDialog(this)) return;

            if (dirty)
            {
                if (byUser)
                {
                    if (!SaveVault()) return;
                }
                else if (!TrySaveQuietly())
                {
                    // Автоблокировка не должна молча потерять несохранённое: если записать
                    // не удалось и сейчас, хранилище остаётся открытым до следующей попытки.
                    idle.Reset();
                    return;
                }
            }

            LockRequested = true;
            CloseOwnedForms(this);
            if (IsHandleCreated)
            {
                BeginInvoke(new MethodInvoker(Close));
            }
            else
            {
                Close();
            }
        }

        private static bool HasBusyDialog(Form form)
        {
            foreach (Form owned in form.OwnedForms)
            {
                var dialog = owned as DialogForm;
                if (dialog != null && dialog.IsBusy) return true;
                if (HasBusyDialog(owned)) return true;
            }
            return false;
        }

        private static void CloseOwnedForms(Form form)
        {
            foreach (Form owned in form.OwnedForms)
            {
                CloseOwnedForms(owned);
                owned.Close();
            }
        }

        internal void ChangeMasterPassword()
        {
            using (var dialog = new ChangePasswordForm(session))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK || LockRequested) return;
            }
            SetDirty(false);
            Flash("Мастер-пароль изменён");
        }

        private void ShowAbout()
        {
            string text =
                Program.AppName + " " + Program.Version + " — портативное хранилище паролей\n\n" +
                "Файл хранилища:\n" + Ui.FitPath(session.FilePath, Ui.Font, MsgBox.TextWidth) + "\n\n" +
                "Шифрование: AES-256-GCM. Ключ получается из мастер-пароля функцией PBKDF2-HMAC-SHA512 (" +
                session.Iterations.ToString("N0") + " итераций).\n\n" +
                "В хранилище: " + Ui.Plural(Data.Groups.Count, "группа", "группы", "групп") + ", " +
                Ui.Plural(Data.Entries.Count, "запись", "записи", "записей") + ".\n\n" +
                "Блокировка — через " + AutoLockMinutes + " мин бездействия, а также при блокировке Windows. " +
                "Буфер обмена очищается через " + ClipboardClearSeconds + " с после копирования.";
            MsgBox.Info(this, "О программе", text);
        }

        private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
        {
            if (e.Reason == SessionSwitchReason.SessionLock || e.Reason == SessionSwitchReason.ConsoleDisconnect ||
                e.Reason == SessionSwitchReason.RemoteDisconnect)
            {
                LockFromSystemEvent();
            }
        }

        private void OnPowerModeChanged(object sender, PowerModeChangedEventArgs e)
        {
            if (e.Mode == PowerModes.Suspend) LockFromSystemEvent();
        }

        private void LockFromSystemEvent()
        {
            if (closing || IsDisposed || !IsHandleCreated) return;
            if (InvokeRequired)
            {
                BeginInvoke(new MethodInvoker(delegate { RequestLock(false); }));
            }
            else
            {
                RequestLock(false);
            }
        }

        // =====================================================================
        //  События элементов управления
        // =====================================================================

        private void OnSearchChanged(object sender, EventArgs e)
        {
            if (suppressSearch) return;

            bool hasSearch = txtSearch.Text.Trim().Length > 0;
            // Поиск начинается по всем группам сразу: искать «не там» — частая причина «не нашлось».
            if (hasSearch && !hadSearch && filter.Kind != FilterKind.All)
            {
                filter = GroupFilter.All;
                RefreshGroups();
            }
            hadSearch = hasSearch;
            RefreshEntries();
        }

        private void OnGroupSelected(object sender, EventArgs e)
        {
            if (refreshing) return;
            var item = lstGroups.SelectedItem as GroupItem;
            if (item == null) return;
            filter = item.ToFilter();
            RefreshEntries();
        }

        private void OnGroupsMouseDown(object sender, MouseEventArgs e)
        {
            // Правый щелчок сначала выбирает группу, затем открывается её меню.
            if (e.Button != MouseButtons.Right) return;
            int index = lstGroups.IndexFromPoint(e.Location);
            if (index >= 0 && index < lstGroups.Items.Count)
            {
                lstGroups.SelectedIndex = index;
            }
        }

        private void OnGroupsKeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.F2)
            {
                RenameGroup();
                e.Handled = true;
            }
            else if (e.KeyCode == Keys.Delete)
            {
                DeleteGroup();
                e.Handled = true;
            }
        }

        private void OnGroupsDragOver(object sender, DragEventArgs e)
        {
            int target = -1;
            if (e.Data.GetDataPresent(DragFormat))
            {
                int index = lstGroups.IndexFromPoint(lstGroups.PointToClient(new Point(e.X, e.Y)));
                if (index >= 0 && index < lstGroups.Items.Count && ((GroupItem)lstGroups.Items[index]).Kind != FilterKind.All)
                {
                    target = index;
                }
            }
            lstGroups.DropIndex = target;
            e.Effect = target >= 0 ? DragDropEffects.Move : DragDropEffects.None;
        }

        private void OnGroupsDragDrop(object sender, DragEventArgs e)
        {
            int target = lstGroups.DropIndex;
            lstGroups.DropIndex = -1;
            if (target < 0 || target >= lstGroups.Items.Count) return;

            var item = (GroupItem)lstGroups.Items[target];
            var ids = e.Data.GetData(DragFormat) as string[];
            if (ids == null || item.Kind == FilterKind.All) return;
            MoveEntries(ids, item.Kind == FilterKind.Group ? item.Id : null);
        }

        private void OnEntriesItemDrag(object sender, ItemDragEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            string[] ids = SelectedIds();
            if (ids.Length == 0) return;
            lvEntries.DoDragDrop(new DataObject(DragFormat, ids), DragDropEffects.Move);
            lstGroups.DropIndex = -1;
        }

        private void OnEntriesKeyDown(object sender, KeyEventArgs e)
        {
            bool handled = true;
            if (e.KeyCode == Keys.Delete && !e.Control && !e.Alt)
            {
                DeleteEntries();
            }
            else if (e.KeyCode == Keys.F2)
            {
                EditEntry();
            }
            else if (e.Control && !e.Alt && e.KeyCode == Keys.C)
            {
                CopyField(true);
            }
            else if (e.Control && !e.Alt && e.KeyCode == Keys.B)
            {
                CopyField(false);
            }
            else if (e.Control && !e.Alt && e.KeyCode == Keys.A)
            {
                foreach (ListViewItem item in lvEntries.Items)
                {
                    item.Selected = true;
                }
            }
            else
            {
                handled = false;
            }

            if (handled)
            {
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
        }

        private void OnColumnClick(object sender, ColumnClickEventArgs e)
        {
            if (e.Column == ColPassword) return; // порядок по паролям выдавал бы сведения о них
            if (e.Column == sortColumn)
            {
                sortAscending = !sortAscending;
            }
            else
            {
                sortColumn = e.Column;
                sortAscending = true;
            }
            RefreshEntries();
        }

        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            switch (keyData)
            {
                case Keys.Insert:
                case Keys.Control | Keys.N:
                    AddEntry();
                    return true;
                case Keys.Control | Keys.G:
                    AddGroup();
                    return true;
                case Keys.Control | Keys.F:
                    txtSearch.Focus();
                    txtSearch.SelectAll();
                    return true;
                case Keys.Control | Keys.H:
                    SetShowPasswords(!showPasswords);
                    return true;
                case Keys.Control | Keys.L:
                    RequestLock(true);
                    return true;
                case Keys.Escape:
                    if (txtSearch.Text.Length > 0)
                    {
                        txtSearch.Text = "";
                        lvEntries.Focus();
                        return true;
                    }
                    break;
            }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        // =====================================================================
        //  Жизненный цикл окна
        // =====================================================================

        private void ApplySavedBounds()
        {
            if (hasSavedBounds)
            {
                foreach (Screen screen in Screen.AllScreens)
                {
                    if (screen.WorkingArea.IntersectsWith(savedBounds))
                    {
                        StartPosition = FormStartPosition.Manual;
                        Bounds = savedBounds;
                        if (savedMaximized) WindowState = FormWindowState.Maximized;
                        return;
                    }
                }
            }
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(Ui.S(1000), Ui.S(600));
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            lvEntries.SetSortArrow(sortColumn, sortAscending);
            AdjustColumns();
            PlaceEmptyLabel();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            if (!LockRequested && dirty && e.CloseReason == CloseReason.UserClosing)
            {
                if (!SaveVault() &&
                    !MsgBox.ConfirmDanger(this, "Выход без сохранения",
                        "Последние изменения не записаны в файл и будут потеряны.\n\nВсё равно выйти?", "Выйти"))
                {
                    e.Cancel = true;
                }
            }

            base.OnFormClosing(e);
            if (e.Cancel) return;

            closing = true;
            savedMaximized = WindowState == FormWindowState.Maximized;
            savedBounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
            hasSavedBounds = true;
            Detach();
        }

        private void Detach()
        {
            tick.Stop();
            ClipboardGuard.Changed -= OnClipboardChanged;
            SystemEvents.SessionSwitch -= OnSessionSwitch;
            SystemEvents.PowerModeChanged -= OnPowerModeChanged;
            Application.RemoveMessageFilter(idle);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Detach();
                tick.Dispose();
                if (rowImages != null) rowImages.Dispose();
                if (rowSpacer != null) rowSpacer.Dispose();
                if (folderIcon != null) folderIcon.Dispose();
                if (entryMenu != null) entryMenu.Dispose();
                if (groupMenu != null) groupMenu.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
