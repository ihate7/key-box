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
        private const string GroupDragFormat = "KeyBox.GroupId";

        // Свёрнутые ветки дерева групп. Как и положение окна, переживают блокировку,
        // но не перезапуск программы: состояние интерфейса в файл хранилища не пишется.
        private static readonly HashSet<string> collapsedGroups = new HashSet<string>();
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
        private ToolStripButton btnGroupEdit;
        private ToolStripButton btnGroupDelete;
        private GroupTree treeGroups;

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

            btnAdd = ToolButton("btnAdd", L.T("Добавить", "Add"), Ui.GlyphAdd, L.T("Новая запись (Ins)", "New entry (Ins)"), true, delegate { AddEntry(); });
            btnEdit = ToolButton("btnEdit", L.T("Изменить", "Edit"), Ui.GlyphEdit, L.T("Изменить запись (Enter)", "Edit entry (Enter)"), true, delegate { EditEntry(); });
            btnDelete = ToolButton("btnDelete", L.T("Удалить", "Delete"), Ui.GlyphDelete, L.T("Удалить выбранные записи (Del)", "Delete selected entries (Del)"), true, delegate { DeleteEntries(); });
            btnCopyLogin = ToolButton("btnCopyLogin", L.T("Логин", "Username"), Ui.GlyphCopy, L.T("Копировать логин (Ctrl+B)", "Copy username (Ctrl+B)"), true, delegate { CopyField(false); });
            btnCopyPassword = ToolButton("btnCopyPassword", L.T("Пароль", "Password"), Ui.GlyphCopy, L.T("Копировать пароль (Ctrl+C)", "Copy password (Ctrl+C)"), true, delegate { CopyField(true); });

            btnMove = new ToolStripDropDownButton(L.T("В группу", "Move to"));
            btnMove.Name = "btnMove";
            StyleToolItem(btnMove, Ui.GlyphMove, L.T("Переместить выбранные записи в другую группу", "Move selected entries to another group"), true);
            btnMove.DropDownItems.Add(new ToolStripMenuItem("…"));
            StyleMenu(btnMove.DropDown);
            btnMove.DropDownOpening += delegate { PopulateMoveMenu(btnMove.DropDownItems); };

            btnShow = ToolButton("btnShow", L.T("Показать пароли", "Show passwords"), Ui.GlyphEye, L.T("Показать или скрыть пароли в списке (Ctrl+H)", "Show or hide passwords in the list (Ctrl+H)"), false, delegate { SetShowPasswords(btnShow.Checked); });
            btnShow.CheckOnClick = true;

            // Правый край: поиск, блокировка, прочее. Выровненные вправо элементы
            // добавляются справа налево.
            btnMore = new ToolStripDropDownButton(L.T("Ещё", "More"));
            btnMore.Name = "btnMore";
            StyleToolItem(btnMore, Ui.GlyphMore, L.T("Смена мастер-пароля, сведения о программе", "Change master password, about the program"), false);
            btnMore.Alignment = ToolStripItemAlignment.Right;
            btnMore.ShowDropDownArrow = false;
            var miChangePassword = new ToolStripMenuItem(L.T("Сменить мастер-пароль…", "Change master password…"));
            miChangePassword.Name = "miChangePassword";
            miChangePassword.Click += delegate { ChangeMasterPassword(); };
            var miAbout = new ToolStripMenuItem(L.T("О программе", "About"));
            miAbout.Name = "miAbout";
            miAbout.Click += delegate { ShowAbout(); };
            StyleMenu(btnMore.DropDown);
            btnMore.DropDownItems.Add(miChangePassword);
            btnMore.DropDownItems.Add(new ToolStripSeparator());
            btnMore.DropDownItems.Add(miAbout);

            btnLock = ToolButton("btnLock", L.T("Заблокировать", "Lock"), Ui.GlyphLock, L.T("Заблокировать хранилище (Ctrl+L)", "Lock the vault (Ctrl+L)"), true, delegate { RequestLock(true); });
            btnLock.Alignment = ToolStripItemAlignment.Right;

            txtSearch = new ToolStripTextBox();
            txtSearch.Name = "txtSearch";
            txtSearch.Alignment = ToolStripItemAlignment.Right;
            txtSearch.Font = Ui.Font;
            txtSearch.BorderStyle = BorderStyle.FixedSingle;
            txtSearch.AutoSize = false;
            txtSearch.Size = new Size(Ui.S(200), txtSearch.TextBox.PreferredHeight);
            txtSearch.Margin = new Padding(Ui.S(6), 0, Ui.S(8), 0);
            txtSearch.ToolTipText = L.T("Поиск по описанию, логину и названию группы (Ctrl+F)", "Search by description, username and group name (Ctrl+F)");
            txtSearch.AccessibleName = L.T("Поиск", "Search");
            txtSearch.TextChanged += OnSearchChanged;
            txtSearch.TextBox.HandleCreated += delegate
            {
                NativeMethods.SendMessage(txtSearch.TextBox.Handle, NativeMethods.EM_SETCUEBANNER, (IntPtr)1, L.T("Поиск", "Search"));
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
            lblPath.ToolTipText = L.T("Файл хранилища: ", "Vault file: ") + session.FilePath;

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

            var caption = new ToolStripLabel(L.T("Группы", "Groups"));
            caption.Font = Ui.BoldFont;
            caption.ForeColor = Ui.TextColor;

            btnGroupDelete = ToolButton("btnGroupDelete", L.T("Удалить группу", "Delete group"), Ui.GlyphDelete, L.T("Удалить группу (Del)", "Delete group (Del)"), false, delegate { DeleteGroup(); });
            btnGroupEdit = ToolButton("btnGroupEdit", L.T("Изменить группу", "Edit group"), Ui.GlyphRename, L.T("Переименовать или перенести группу (F2)", "Rename or move the group (F2)"), false, delegate { EditGroup(); });
            btnGroupAdd = ToolButton("btnGroupAdd", L.T("Новая группа", "New group"), Ui.GlyphAdd, L.T("Новая группа (Ctrl+G)", "New group (Ctrl+G)"), false, delegate { AddGroup(); });
            btnGroupDelete.Alignment = ToolStripItemAlignment.Right;
            btnGroupEdit.Alignment = ToolStripItemAlignment.Right;
            btnGroupAdd.Alignment = ToolStripItemAlignment.Right;
            if (!Ui.HasGlyphs)
            {
                // Без шрифта со значками кнопки показывают текст, а полные названия
                // в узкую панель не помещаются — оставляем короткие обозначения.
                btnGroupAdd.Text = "+";
                btnGroupEdit.Text = L.T("Изм.", "Edit");
                btnGroupDelete.Text = "×";
            }

            groupBar.Items.AddRange(new ToolStripItem[] { caption, btnGroupDelete, btnGroupEdit, btnGroupAdd });

            treeGroups = new GroupTree();
            treeGroups.Name = "treeGroups";
            treeGroups.Dock = DockStyle.Fill;
            treeGroups.AllowDrop = true;
            treeGroups.AccessibleName = L.T("Группы", "Groups");
            treeGroups.AfterSelect += OnGroupSelected;
            treeGroups.AfterCollapse += delegate(object sender, TreeViewEventArgs e) { RememberCollapsed(e.Node, true); };
            treeGroups.AfterExpand += delegate(object sender, TreeViewEventArgs e) { RememberCollapsed(e.Node, false); };
            treeGroups.MouseDown += OnGroupsMouseDown;
            treeGroups.KeyDown += OnGroupsKeyDown;
            treeGroups.ItemDrag += OnGroupsItemDrag;
            treeGroups.DragOver += OnGroupsDragOver;
            treeGroups.DragLeave += delegate { treeGroups.DropNode = null; };
            treeGroups.DragDrop += OnGroupsDragDrop;

            pane.Controls.Add(treeGroups);
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
            lvEntries.AccessibleName = L.T("Записи", "Entries");
            colDescription = lvEntries.Columns.Add(L.T("Описание", "Description"), Ui.S(300));
            colLogin = lvEntries.Columns.Add(L.T("Логин", "Username"), Ui.S(190));
            colPassword = lvEntries.Columns.Add(L.T("Пароль", "Password"), Ui.S(120));
            colGroup = lvEntries.Columns.Add(L.T("Группа", "Group"), Ui.S(210));

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

            ToolStripMenuItem miCopyPassword = MenuItem(L.T("Копировать пароль", "Copy password"), "Ctrl+C", delegate { CopyField(true); });
            ToolStripMenuItem miCopyLogin = MenuItem(L.T("Копировать логин", "Copy username"), "Ctrl+B", delegate { CopyField(false); });
            ToolStripMenuItem miEdit = MenuItem(L.T("Изменить…", "Edit…"), "Enter", delegate { EditEntry(); });
            var miMove = new ToolStripMenuItem(L.T("Переместить в группу", "Move to group"));
            miMove.DropDownItems.Add(new ToolStripMenuItem("…"));
            StyleMenu(miMove.DropDown);
            miMove.DropDownOpening += delegate { PopulateMoveMenu(miMove.DropDownItems); };
            ToolStripMenuItem miDelete = MenuItem(L.T("Удалить", "Delete"), "Del", delegate { DeleteEntries(); });
            ToolStripMenuItem miAdd = MenuItem(L.T("Новая запись…", "New entry…"), "Ins", delegate { AddEntry(); });

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
            ToolStripMenuItem miGroupAdd = MenuItem(L.T("Новая группа…", "New group…"), "Ctrl+G", delegate { AddGroup(); });
            ToolStripMenuItem miGroupEdit = MenuItem(L.T("Изменить…", "Edit…"), "F2", delegate { EditGroup(); });
            ToolStripMenuItem miGroupDelete = MenuItem(L.T("Удалить группу", "Delete group"), "Del", delegate { DeleteGroup(); });
            groupMenu.Items.AddRange(new ToolStripItem[] { miGroupAdd, new ToolStripSeparator(), miGroupEdit, miGroupDelete });
            groupMenu.Opening += delegate
            {
                bool isGroup = SelectedGroup() != null;
                miGroupEdit.Enabled = isGroup;
                miGroupDelete.Enabled = isGroup;
            };
            treeGroups.ContextMenuStrip = groupMenu;
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

        /// <summary>Все группы в порядке дерева: группа, за ней её подгруппы; соседние — по названию.</summary>
        private List<Group> GroupsInTreeOrder()
        {
            return Data.TreeOrder(Ui.CompareNatural);
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
            treeGroups.BeginUpdate();
            try
            {
                treeGroups.Nodes.Clear();

                TreeNode all = MakeGroupNode(FilterKind.All, null, L.T("Все записи", "All entries"), Data.Entries.Count);
                treeGroups.Nodes.Add(all);

                // Родительская группа в этом порядке всегда идёт раньше своих подгрупп.
                var nodes = new Dictionary<string, TreeNode>();
                foreach (Group group in GroupsInTreeOrder())
                {
                    TreeNode node = MakeGroupNode(FilterKind.Group, group.Id, group.Name, counts[group.Id]);
                    TreeNode parent;
                    if (group.ParentId != null && nodes.TryGetValue(group.ParentId, out parent))
                    {
                        parent.Nodes.Add(node);
                    }
                    else
                    {
                        treeGroups.Nodes.Add(node);
                    }
                    nodes[group.Id] = node;
                }

                TreeNode none = MakeGroupNode(FilterKind.Ungrouped, null, L.T("Без группы", "No group"), ungrouped);
                treeGroups.Nodes.Add(none);

                // Ветки раскрыты, кроме тех, что пользователь свернул сам.
                foreach (KeyValuePair<string, TreeNode> pair in nodes)
                {
                    if (pair.Value.Nodes.Count > 0 && !collapsedGroups.Contains(pair.Key)) pair.Value.Expand();
                }

                TreeNode selected;
                if (filter.Kind == FilterKind.Group) selected = nodes[filter.GroupId];
                else selected = filter.Kind == FilterKind.Ungrouped ? none : all;
                treeGroups.SelectedNode = selected;
            }
            finally
            {
                treeGroups.EndUpdate();
                refreshing = false;
            }
            UpdateCommands();
        }

        private static TreeNode MakeGroupNode(FilterKind kind, string id, string name, int count)
        {
            var item = new GroupItem();
            item.Kind = kind;
            item.Id = id;
            item.Name = name;
            item.Count = count;

            var node = new TreeNode(name);
            node.Tag = item;
            return node;
        }

        /// <summary>Запоминает, какие ветки свёрнуты, чтобы обновление списка их не раскрывало.</summary>
        private static void RememberCollapsed(TreeNode node, bool collapsed)
        {
            var item = node == null ? null : node.Tag as GroupItem;
            if (item == null || item.Id == null) return;
            if (collapsed) collapsedGroups.Add(item.Id);
            else collapsedGroups.Remove(item.Id);
        }

        private void RefreshEntries()
        {
            var selected = new HashSet<string>(SelectedIds());
            string focusedId = lvEntries.FocusedItem == null ? null : (string)lvEntries.FocusedItem.Tag;

            // В столбце «Группа» показывается полный путь: «Работа / Проекты».
            Dictionary<string, string> groupNames = Data.GroupPaths();

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
                text = L.T("Здесь пока пусто.\nНажмите «Добавить», чтобы создать первую запись.", "Nothing here yet.\nClick “Add” to create the first entry.");
            }
            else if (txtSearch.Text.Trim().Length > 0)
            {
                text = L.T("Ничего не найдено.", "Nothing found.");
            }
            else if (filter.Kind == FilterKind.Ungrouped)
            {
                text = L.T("Записей без группы нет.", "There are no entries without a group.");
            }
            else if (Data.CountInBranch(filter.GroupId) > 0)
            {
                // Группа показывает только свои записи, а здесь все они разложены по подгруппам.
                text = L.T("В самой группе записей нет — они лежат в её подгруппах.\nВыберите подгруппу слева или воспользуйтесь поиском.", "This group itself has no entries — they are in its subgroups.\nPick a subgroup on the left or use the search.");
            }
            else
            {
                text = L.T("В этой группе пока нет записей.\nПеретащите записи на группу в списке слева или нажмите «Добавить».", "This group has no entries yet.\nDrag entries onto the group on the left or click “Add”.");
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
                ? L.F("Записей: {0}", "Entries: {0}", total)
                : L.F("Показано: {0} из {1}", "Showing {0} of {1}", shown, total);
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
            btnGroupEdit.Enabled = isGroup;
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
                text = L.T("Внимание: последние изменения не записаны в файл", "Warning: the latest changes have not been written to the file");
                color = Ui.Danger;
            }
            else if (flashSeconds > 0)
            {
                text = flashText;
            }
            else if (ClipboardGuard.Pending)
            {
                text = L.F("{0} скопирован. Буфер обмена очистится через {1} с",
                    "{0} copied. The clipboard will be cleared in {1} s",
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
                Flash(L.T("Буфер обмена очищен", "Clipboard cleared"));
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
                bool retry = MsgBox.Retry(this, L.T("Не удалось сохранить", "Could not save"),
                    problem + L.T("\n\nИзменения пока остаются только в памяти программы. " +
                                  "Проверьте, что носитель на месте и доступен для записи, и повторите попытку.",
                                  "\n\nFor now the changes are kept only in the program's memory. " +
                                  "Make sure the drive is present and writable, then try again."));
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
                    MsgBox.Error(this, L.T("Новая запись", "New entry"), ex.Message);
                    return;
                }
                SaveVault();
                RevealEntry(entry);
                Flash(L.T("Запись добавлена", "Entry added"));
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
                    MsgBox.Error(this, L.T("Изменение записи", "Edit entry"), ex.Message);
                    RefreshAll();
                    return;
                }
                if (!changed) return;

                SaveVault();
                RevealEntry(entry);
                Flash(L.T("Запись сохранена", "Entry saved"));
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
                question = L.F("Удалить запись «{0}»?\n\nВосстановить её будет нельзя.",
                    "Delete the entry “{0}”?\n\nIt cannot be restored.", TitleOf(entry));
            }
            else
            {
                question = L.F("Удалить {0}?\n\nВосстановить их будет нельзя.", "Delete {0}?\n\nThey cannot be restored.",
                    L.Plural(ids.Length, "выбранную запись", "выбранные записи", "выбранных записей", "selected entry", "selected entries"));
            }
            if (!MsgBox.ConfirmDanger(this, L.T("Удаление", "Delete"), question, L.T("Удалить", "Delete")) || LockRequested) return;

            int removed = Data.DeleteEntries(ids);
            SaveVault();
            RefreshAll();
            Flash(L.F("Удалено: {0}", "Deleted: {0}", L.Plural(removed, "запись", "записи", "записей", "entry", "entries")));
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

            string what = password ? L.T("Пароль", "Password") : L.T("Логин", "Username");
            string value = password ? entry.Password : entry.Login;
            if (string.IsNullOrEmpty(value))
            {
                Flash(password
                    ? L.T("Пароль у этой записи не задан", "This entry has no password")
                    : L.T("Логин у этой записи не задан", "This entry has no username"));
                return;
            }
            if (!ClipboardGuard.Copy(value, what, ClipboardClearSeconds))
            {
                Flash(L.T("Не удалось скопировать: буфер обмена занят другой программой", "Could not copy: the clipboard is in use by another program"));
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
                MsgBox.Error(this, L.T("Перемещение", "Move"), ex.Message);
                RefreshAll();
                return;
            }

            if (moved == 0)
            {
                Flash(groupId == null
                    ? L.T("Эти записи и так без группы", "These entries have no group already")
                    : L.T("Записи уже в этой группе", "The entries are already in this group"));
                return;
            }
            SaveVault();
            RefreshAll();

            string count = L.Plural(moved, "запись", "записи", "записей", "entry", "entries");
            Flash(groupId == null
                ? L.F("Перемещено в «Без группы»: {0}", "Moved to “No group”: {0}", count)
                : L.F("Перемещено в группу «{0}»: {1}", "Moved to the group “{0}”: {1}", Ui.Shorten(Data.GroupPath(groupId), 60), count));
        }

        private void MoveSelectedToNewGroup()
        {
            string[] ids = SelectedIds();
            if (ids.Length == 0) return;
            Group group = PromptNewGroup(SuggestedParentId());
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

            List<Group> groups = GroupsInTreeOrder();
            foreach (Group group in groups)
            {
                string targetId = group.Id;
                var item = new ToolStripMenuItem(Ui.MenuText(Data.GroupPath(group.Id)));
                item.Image = folderIcon;
                item.Enabled = !(sameGroup && common == targetId);
                item.Click += delegate { MoveEntries(SelectedIds(), targetId); };
                items.Add(item);
            }
            if (groups.Count > 0) items.Add(new ToolStripSeparator());

            var none = new ToolStripMenuItem(L.T("Без группы", "No group"));
            none.Enabled = !(sameGroup && common == "");
            none.Click += delegate { MoveEntries(SelectedIds(), null); };
            items.Add(none);

            items.Add(new ToolStripSeparator());
            var create = new ToolStripMenuItem(L.T("Новая группа…", "New group…"));
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

        /// <summary>
        /// Где предложить создать новую группу: внутри выбранной в дереве,
        /// а если выбрана не группа — на верхнем уровне. В окне это можно поменять.
        /// </summary>
        private string SuggestedParentId()
        {
            return filter.Kind == FilterKind.Group ? filter.GroupId : null;
        }

        private Group PromptNewGroup(string parentId)
        {
            using (var dialog = new GroupForm(Data, null, parentId))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK || LockRequested) return null;

                try
                {
                    return Data.AddGroup(dialog.GroupName, dialog.ParentId);
                }
                catch (ValidationException ex)
                {
                    MsgBox.Error(this, L.T("Новая группа", "New group"), ex.Message);
                    return null;
                }
            }
        }

        internal void AddGroup()
        {
            Group group = PromptNewGroup(SuggestedParentId());
            if (group == null) return;

            SaveVault();
            SetSearchSilently("");
            filter = GroupFilter.ForGroup(group.Id);
            RefreshAll();
            Flash(L.F("Группа «{0}» создана", "Group “{0}” created", Ui.Shorten(Data.GroupPath(group.Id), 60)));
        }

        /// <summary>Меняет название выбранной группы и её место в дереве.</summary>
        internal void EditGroup()
        {
            Group group = SelectedGroup();
            if (group == null) return;

            using (var dialog = new GroupForm(Data, group, group.ParentId))
            {
                if (dialog.ShowDialog(this) != DialogResult.OK || LockRequested) return;

                bool moved = dialog.ParentId != group.ParentId;
                bool changed;
                try
                {
                    changed = Data.UpdateGroup(group.Id, dialog.GroupName, dialog.ParentId);
                }
                catch (ValidationException ex)
                {
                    MsgBox.Error(this, L.T("Изменение группы", "Edit group"), ex.Message);
                    RefreshAll();
                    return;
                }
                if (!changed) return;

                SaveVault();
                RefreshAll();
                Flash(moved
                    ? L.F("Группа перенесена: «{0}»", "Group moved: “{0}”", Ui.Shorten(Data.GroupPath(group.Id), 60))
                    : L.T("Группа переименована", "Group renamed"));
            }
        }

        /// <summary>Переносит группу в другую (null — на верхний уровень); используется при перетаскивании.</summary>
        private void MoveGroup(string groupId, string parentId)
        {
            bool changed;
            try
            {
                changed = Data.MoveGroup(groupId, parentId);
            }
            catch (ValidationException ex)
            {
                MsgBox.Error(this, L.T("Перенос группы", "Move group"), ex.Message);
                RefreshAll();
                return;
            }
            if (!changed) return;

            SaveVault();
            RefreshAll();
            Flash(L.F("Группа перенесена: «{0}»", "Group moved: “{0}”", Ui.Shorten(Data.GroupPath(groupId), 60)));
        }

        internal void DeleteGroup()
        {
            Group group = SelectedGroup();
            if (group == null) return;

            // Вместе с группой удаляются её подгруппы, а записи всей ветки переходят на уровень выше.
            int subgroups = Data.DescendantsOf(group.Id).Count;
            int entries = Data.CountInBranch(group.Id);
            Group parent = Data.FindGroup(group.ParentId);

            string question = L.F("Удалить группу «{0}»", "Delete the group “{0}”", Ui.Shorten(group.Name, 60));
            if (subgroups == 1)
            {
                question += L.T(" вместе с её подгруппой", " together with its subgroup");
            }
            else if (subgroups > 1)
            {
                question += L.F(" вместе с её подгруппами ({0})", " together with its subgroups ({0})", subgroups);
            }
            question += "?";
            if (entries > 0)
            {
                string count = L.Plural(entries, "запись", "записи", "записей", "entry", "entries");
                string verb = entries == 1 ? L.T("окажется", "will move") : L.T("окажутся", "will move");
                question += "\n\n" + (parent == null
                    ? L.F("Записи при этом не удаляются: {0} {1} в разделе «Без группы».",
                          "The entries are not deleted: {0} {1} to “No group”.", count, verb)
                    : L.F("Записи при этом не удаляются: {0} {1} в группе «{2}».",
                          "The entries are not deleted: {0} {1} to the group “{2}”.", count, verb, Ui.Shorten(parent.Name, 40)));
            }
            if (!MsgBox.ConfirmDanger(this, L.T("Удаление группы", "Delete group"), question, L.T("Удалить группу", "Delete group")) || LockRequested) return;

            try
            {
                Data.DeleteGroup(group.Id);
            }
            catch (ValidationException ex)
            {
                MsgBox.Error(this, L.T("Удаление группы", "Delete group"), ex.Message);
                RefreshAll();
                return;
            }
            SaveVault();

            // Показываем место, куда попали записи удалённой ветки.
            if (parent != null) filter = GroupFilter.ForGroup(parent.Id);
            else filter = entries > 0 ? GroupFilter.Ungrouped : GroupFilter.All;
            RefreshAll();
            Flash(L.T("Группа удалена", "Group deleted"));
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
            Flash(L.T("Мастер-пароль изменён", "Master password changed"));
        }

        private void ShowAbout()
        {
            string text = L.F(
                "{0} {1} — портативное хранилище паролей\n\n" +
                "Файл хранилища:\n{2}\n\n" +
                "Шифрование: AES-256-GCM. Ключ получается из мастер-пароля функцией PBKDF2-HMAC-SHA512 ({3} итераций).\n\n" +
                "В хранилище: {4}, {5}.\n\n" +
                "Блокировка — через {6} мин бездействия, а также при блокировке Windows. " +
                "Буфер обмена очищается через {7} с после копирования.",
                "{0} {1} — a portable password vault\n\n" +
                "Vault file:\n{2}\n\n" +
                "Encryption: AES-256-GCM. The key is derived from the master password with PBKDF2-HMAC-SHA512 ({3} iterations).\n\n" +
                "In the vault: {4}, {5}.\n\n" +
                "Auto-lock after {6} min of inactivity and when Windows is locked. " +
                "The clipboard is cleared {7} s after copying.",
                Program.AppName, Program.Version,
                Ui.FitPath(session.FilePath, Ui.Font, MsgBox.TextWidth),
                session.Iterations.ToString("N0"),
                L.Plural(Data.Groups.Count, "группа", "группы", "групп", "group", "groups"),
                L.Plural(Data.Entries.Count, "запись", "записи", "записей", "entry", "entries"),
                AutoLockMinutes, ClipboardClearSeconds);
            MsgBox.Info(this, L.T("О программе", "About"), text);
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

        private void OnGroupSelected(object sender, TreeViewEventArgs e)
        {
            if (refreshing) return;
            var item = e.Node == null ? null : e.Node.Tag as GroupItem;
            if (item == null) return;
            filter = item.ToFilter();
            RefreshEntries();
        }

        private void OnGroupsMouseDown(object sender, MouseEventArgs e)
        {
            // Правый щелчок сначала выбирает группу, затем открывается её меню.
            if (e.Button != MouseButtons.Right) return;
            TreeNode node = treeGroups.GetNodeAt(e.Location);
            if (node != null) treeGroups.SelectedNode = node;
        }

        private void OnGroupsKeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.F2)
            {
                EditGroup();
                e.Handled = true;
            }
            else if (e.KeyCode == Keys.Delete)
            {
                DeleteGroup();
                e.Handled = true;
            }
        }

        /// <summary>Группу можно перетащить мышью в другую группу или на «Все записи» — на верхний уровень.</summary>
        private void OnGroupsItemDrag(object sender, ItemDragEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            var node = e.Item as TreeNode;
            var item = node == null ? null : node.Tag as GroupItem;
            if (item == null || item.Kind != FilterKind.Group) return;

            treeGroups.DoDragDrop(new DataObject(GroupDragFormat, item.Id), DragDropEffects.Move);
            treeGroups.DropNode = null;
        }

        /// <summary>
        /// Определяет, куда упадёт перетаскиваемое. Возвращает строку дерева, которую нужно
        /// подсветить, или null, если бросать сюда нельзя.
        /// </summary>
        private TreeNode FindDropTarget(DragEventArgs e)
        {
            TreeNode node = treeGroups.GetNodeAt(treeGroups.PointToClient(new Point(e.X, e.Y)));
            var item = node == null ? null : node.Tag as GroupItem;

            if (e.Data.GetDataPresent(DragFormat))
            {
                // Записи — в любую группу или в «Без группы».
                return item != null && item.Kind != FilterKind.All ? node : null;
            }

            if (e.Data.GetDataPresent(GroupDragFormat))
            {
                Group group = Data.FindGroup(e.Data.GetData(GroupDragFormat) as string);
                if (group == null || treeGroups.Nodes.Count == 0) return null;

                // «Все записи» и свободное место под деревом означают верхний уровень.
                if (item == null || item.Kind == FilterKind.All)
                {
                    return group.ParentId == null ? null : treeGroups.Nodes[0];
                }
                // Нельзя: в «Без группы», туда, где группа уже лежит, в саму себя и в свои подгруппы.
                if (item.Kind != FilterKind.Group || item.Id == group.ParentId) return null;
                return Data.ValidateGroupParent(group.Id, item.Id) == null ? node : null;
            }
            return null;
        }

        private void OnGroupsDragOver(object sender, DragEventArgs e)
        {
            TreeNode target = FindDropTarget(e);
            treeGroups.DropNode = target;
            e.Effect = target != null ? DragDropEffects.Move : DragDropEffects.None;
        }

        private void OnGroupsDragDrop(object sender, DragEventArgs e)
        {
            TreeNode target = FindDropTarget(e);
            treeGroups.DropNode = null;
            var item = target == null ? null : target.Tag as GroupItem;
            if (item == null) return;

            string targetId = item.Kind == FilterKind.Group ? item.Id : null;
            if (e.Data.GetDataPresent(DragFormat))
            {
                var ids = e.Data.GetData(DragFormat) as string[];
                if (ids != null) MoveEntries(ids, targetId);
            }
            else if (e.Data.GetDataPresent(GroupDragFormat))
            {
                var groupId = e.Data.GetData(GroupDragFormat) as string;
                if (groupId != null) MoveGroup(groupId, targetId);
            }
        }

        private void OnEntriesItemDrag(object sender, ItemDragEventArgs e)
        {
            if (e.Button != MouseButtons.Left) return;
            string[] ids = SelectedIds();
            if (ids.Length == 0) return;
            lvEntries.DoDragDrop(new DataObject(DragFormat, ids), DragDropEffects.Move);
            treeGroups.DropNode = null;
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
                    !MsgBox.ConfirmDanger(this, L.T("Выход без сохранения", "Exit without saving"),
                        L.T("Последние изменения не записаны в файл и будут потеряны.\n\nВсё равно выйти?",
                            "The latest changes have not been written to the file and will be lost.\n\nExit anyway?"),
                        L.T("Выйти", "Exit")))
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
