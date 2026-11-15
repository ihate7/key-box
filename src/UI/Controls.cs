using System;
using System.Drawing;
using System.Windows.Forms;
using KeyBox.Vault;

namespace KeyBox.UI
{
    /// <summary>Плоское оформление панелей инструментов и меню.</summary>
    internal sealed class FlatRenderer : ToolStripProfessionalRenderer
    {
        /// <summary>Tag панели, под которой нужно провести разделительную линию.</summary>
        public const string LineBelow = "line-below";

        public FlatRenderer()
            : base(new FlatColors())
        {
            RoundedEdges = false;
        }

        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
        {
            if (e.ToolStrip is ToolStripDropDown)
            {
                base.OnRenderToolStripBackground(e);
                return;
            }
            using (var brush = new SolidBrush(e.ToolStrip.BackColor))
            {
                e.Graphics.FillRectangle(brush, e.AffectedBounds);
            }
        }

        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
        {
            ToolStrip strip = e.ToolStrip;
            if (strip is ToolStripDropDown)
            {
                base.OnRenderToolStripBorder(e);
                return;
            }
            using (var pen = new Pen(Ui.Line))
            {
                if (strip is StatusStrip)
                {
                    e.Graphics.DrawLine(pen, 0, 0, strip.Width, 0);
                }
                else if (LineBelow.Equals(strip.Tag))
                {
                    e.Graphics.DrawLine(pen, 0, strip.Height - 1, strip.Width, strip.Height - 1);
                }
            }
        }
    }

    internal sealed class FlatColors : ProfessionalColorTable
    {
        public FlatColors()
        {
            UseSystemColors = false;
        }

        public override Color ButtonSelectedHighlight { get { return Ui.HoverBack; } }
        public override Color ButtonSelectedHighlightBorder { get { return Ui.HoverBorder; } }
        public override Color ButtonSelectedBorder { get { return Ui.HoverBorder; } }
        public override Color ButtonSelectedGradientBegin { get { return Ui.HoverBack; } }
        public override Color ButtonSelectedGradientMiddle { get { return Ui.HoverBack; } }
        public override Color ButtonSelectedGradientEnd { get { return Ui.HoverBack; } }

        public override Color ButtonPressedHighlight { get { return Ui.PressedBack; } }
        public override Color ButtonPressedHighlightBorder { get { return Ui.HoverBorder; } }
        public override Color ButtonPressedBorder { get { return Ui.HoverBorder; } }
        public override Color ButtonPressedGradientBegin { get { return Ui.PressedBack; } }
        public override Color ButtonPressedGradientMiddle { get { return Ui.PressedBack; } }
        public override Color ButtonPressedGradientEnd { get { return Ui.PressedBack; } }

        public override Color ButtonCheckedHighlight { get { return Ui.SelectedBack; } }
        public override Color ButtonCheckedHighlightBorder { get { return Ui.HoverBorder; } }
        public override Color ButtonCheckedGradientBegin { get { return Ui.SelectedBack; } }
        public override Color ButtonCheckedGradientMiddle { get { return Ui.SelectedBack; } }
        public override Color ButtonCheckedGradientEnd { get { return Ui.SelectedBack; } }

        public override Color CheckBackground { get { return Ui.SelectedBack; } }
        public override Color CheckSelectedBackground { get { return Ui.SelectedBack; } }
        public override Color CheckPressedBackground { get { return Ui.PressedBack; } }

        public override Color MenuBorder { get { return Color.FromArgb(200, 204, 211); } }
        public override Color MenuItemBorder { get { return Ui.HoverBorder; } }
        public override Color MenuItemSelected { get { return Ui.HoverBack; } }
        public override Color MenuItemSelectedGradientBegin { get { return Ui.HoverBack; } }
        public override Color MenuItemSelectedGradientEnd { get { return Ui.HoverBack; } }
        public override Color MenuItemPressedGradientBegin { get { return Ui.PressedBack; } }
        public override Color MenuItemPressedGradientMiddle { get { return Ui.PressedBack; } }
        public override Color MenuItemPressedGradientEnd { get { return Ui.PressedBack; } }

        public override Color ToolStripDropDownBackground { get { return SystemColors.Window; } }
        public override Color ImageMarginGradientBegin { get { return SystemColors.Window; } }
        public override Color ImageMarginGradientMiddle { get { return SystemColors.Window; } }
        public override Color ImageMarginGradientEnd { get { return SystemColors.Window; } }

        public override Color SeparatorDark { get { return Ui.Line; } }
        public override Color SeparatorLight { get { return SystemColors.Window; } }
        public override Color ToolStripBorder { get { return Ui.Line; } }
        public override Color GripDark { get { return Ui.Line; } }
        public override Color GripLight { get { return SystemColors.Window; } }

        public override Color OverflowButtonGradientBegin { get { return SystemColors.Window; } }
        public override Color OverflowButtonGradientMiddle { get { return SystemColors.Window; } }
        public override Color OverflowButtonGradientEnd { get { return Ui.HoverBack; } }
    }

    /// <summary>Строка в дереве групп: «Все записи», обычная группа, «Без группы» или «Корзина».</summary>
    internal sealed class GroupItem
    {
        public FilterKind Kind;
        public string Id;
        public string Name;
        public int Count;

        public GroupFilter ToFilter()
        {
            switch (Kind)
            {
                case FilterKind.Group:
                    return GroupFilter.ForGroup(Id);
                case FilterKind.Ungrouped:
                    return GroupFilter.Ungrouped;
                case FilterKind.Trash:
                    return GroupFilter.Trash;
                default:
                    return GroupFilter.All;
            }
        }

        public override string ToString()
        {
            return Name;
        }
    }

    /// <summary>
    /// Дерево групп слева: значок, название, число записей, подсветка при перетаскивании.
    /// Группы можно вкладывать друг в друга; ветка сворачивается стрелкой, двойным щелчком
    /// и клавишами «влево» и «вправо». Строки рисует программа, а всё поведение дерева
    /// (выбор, клавиатура, раскрытие, доступность для экранных дикторов) — стандартное.
    /// </summary>
    internal sealed class GroupTree : TreeView
    {
        private const int TVS_NOHSCROLL = 0x8000;
        private const int TVM_SETEXTENDEDSTYLE = 0x112C;
        private const int TVS_EX_DOUBLEBUFFER = 0x0004;
        private const int WM_LBUTTONDOWN = 0x0201;
        private const int WM_LBUTTONDBLCLK = 0x0203;

        private readonly Bitmap iconAll;
        private readonly Bitmap iconGroup;
        private readonly Bitmap iconNone;
        private readonly Bitmap iconTrash;
        private readonly Bitmap arrowClosed;
        private readonly Bitmap arrowOpen;
        private TreeNode dropNode;

        public GroupTree()
        {
            DrawMode = TreeViewDrawMode.OwnerDrawAll;
            ShowLines = false;
            ShowPlusMinus = false;
            ShowRootLines = false;
            FullRowSelect = true;
            HideSelection = false;
            BorderStyle = BorderStyle.None;
            ItemHeight = Ui.S(30);
            Indent = LevelIndent;
            BackColor = Ui.PaneBack;
            ForeColor = Ui.TextColor;
            Font = Ui.Font;

            iconAll = Ui.Glyph(Ui.GlyphList, 16, Ui.GlyphColor);
            iconGroup = Ui.Glyph(Ui.GlyphFolder, 16, Ui.GlyphColor);
            iconNone = Ui.Glyph(Ui.GlyphPage, 16, Ui.Muted);
            iconTrash = Ui.Glyph(Ui.GlyphDelete, 16, Ui.Muted);
            arrowClosed = Ui.Glyph(Ui.GlyphChevronRight, 10, Ui.Muted);
            arrowOpen = Ui.Glyph(Ui.GlyphChevronDown, 10, Ui.Muted);
        }

        /// <summary>Сдвиг вправо на каждый уровень вложенности.</summary>
        private static int LevelIndent
        {
            get { return Ui.S(16); }
        }

        /// <summary>Ширина области стрелки, которая сворачивает и раскрывает ветку.</summary>
        private static int ArrowWidth
        {
            get { return Ui.S(18); }
        }

        /// <summary>
        /// Строка, которая сейчас подсвечена как место, куда упадёт перетаскиваемое;
        /// null — подсветки нет.
        /// </summary>
        public TreeNode DropNode
        {
            get { return dropNode; }
            set
            {
                if (dropNode == value) return;
                TreeNode old = dropNode;
                dropNode = value;
                InvalidateRow(old);
                InvalidateRow(value);
            }
        }

        /// <summary>Область стрелки у строки (есть только у групп с подгруппами).</summary>
        public Rectangle ArrowBounds(TreeNode node)
        {
            Rectangle label = node.Bounds;
            return new Rectangle(Ui.S(6) + node.Level * LevelIndent, label.Y, ArrowWidth, label.Height);
        }

        private void InvalidateRow(TreeNode node)
        {
            if (node == null || !IsHandleCreated || node.TreeView != this) return;
            Rectangle label = node.Bounds;
            if (label.Height > 0) Invalidate(new Rectangle(0, label.Y, ClientSize.Width, label.Height));
        }

        protected override CreateParams CreateParams
        {
            get
            {
                // Длинные названия обрезаются многоточием, горизонтальная прокрутка не нужна.
                CreateParams parameters = base.CreateParams;
                parameters.Style |= TVS_NOHSCROLL;
                return parameters;
            }
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SendMessage(Handle, TVM_SETEXTENDEDSTYLE, (IntPtr)TVS_EX_DOUBLEBUFFER, (IntPtr)TVS_EX_DOUBLEBUFFER);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_LBUTTONDOWN || m.Msg == WM_LBUTTONDBLCLK)
            {
                long packed = m.LParam.ToInt64();
                var point = new Point((short)(packed & 0xFFFF), (short)((packed >> 16) & 0xFFFF));
                TreeNode node = GetNodeAt(point);
                if (node != null && node.Nodes.Count > 0 && ArrowBounds(node).Contains(point))
                {
                    // Щелчок по стрелке только сворачивает или раскрывает ветку и не меняет выбранную группу.
                    // Сворачивается только сама группа: вложенные ветки остаются как были и при
                    // повторном раскрытии выглядят по-прежнему (Toggle() свернул бы и их).
                    Focus();
                    if (node.IsExpanded) node.Collapse(true);
                    else node.Expand();
                    return;
                }
            }
            base.WndProc(ref m);
        }

        protected override void OnDrawNode(DrawTreeNodeEventArgs e)
        {
            TreeNode node = e.Node;
            var item = node == null ? null : node.Tag as GroupItem;
            if (item == null || e.Bounds.Height <= 0) return;

            Graphics g = e.Graphics;
            var bounds = new Rectangle(0, e.Bounds.Y, ClientSize.Width, e.Bounds.Height);
            bool selected = node.IsSelected;
            bool drop = node == dropNode;

            Color back = drop ? Ui.DropBack : (selected ? Ui.SelectedBack : BackColor);
            using (var brush = new SolidBrush(back))
            {
                g.FillRectangle(brush, bounds);
            }
            if (selected)
            {
                using (var brush = new SolidBrush(Ui.Accent))
                {
                    g.FillRectangle(brush, bounds.X, bounds.Y + Ui.S(6), Ui.S(3), bounds.Height - Ui.S(12));
                }
            }
            if (drop)
            {
                using (var pen = new Pen(Ui.Accent))
                {
                    g.DrawRectangle(pen, bounds.X, bounds.Y, bounds.Width - 1, bounds.Height - 1);
                }
            }

            bool builtIn = item.Kind == FilterKind.Ungrouped || item.Kind == FilterKind.Trash;
            Color textColor = (selected || drop) ? Ui.SelectedText : (builtIn ? Ui.Muted : ForeColor);
            Color countColor = (selected || drop) ? Ui.SelectedText : Ui.Muted;

            // Стрелка ветки, затем значок, название и справа — число записей.
            Rectangle arrowArea = ArrowBounds(node);
            if (node.Nodes.Count > 0)
            {
                Bitmap arrow = node.IsExpanded ? arrowOpen : arrowClosed;
                if (arrow != null)
                {
                    g.DrawImage(arrow, arrowArea.X + (arrowArea.Width - arrow.Width) / 2,
                        bounds.Y + (bounds.Height - arrow.Height) / 2, arrow.Width, arrow.Height);
                }
                else
                {
                    DrawPlainArrow(g, arrowArea, node.IsExpanded);
                }
            }

            int x = arrowArea.Right;
            Bitmap icon;
            if (item.Kind == FilterKind.All) icon = iconAll;
            else if (item.Kind == FilterKind.Group) icon = iconGroup;
            else icon = item.Kind == FilterKind.Trash ? iconTrash : iconNone;
            if (icon != null)
            {
                g.DrawImage(icon, x, bounds.Y + (bounds.Height - icon.Height) / 2, icon.Width, icon.Height);
                x += icon.Width + Ui.S(8);
            }

            const TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding;

            string count = item.Count.ToString();
            Size countSize = TextRenderer.MeasureText(g, count, Font, Size.Empty, flags);
            var countBounds = new Rectangle(bounds.Right - Ui.S(12) - countSize.Width, bounds.Y, countSize.Width, bounds.Height);
            TextRenderer.DrawText(g, count, Font, countBounds, countColor, flags);

            var textBounds = new Rectangle(x, bounds.Y, Math.Max(0, countBounds.X - Ui.S(8) - x), bounds.Height);
            TextRenderer.DrawText(g, item.Name, Font, textBounds, textColor, flags | TextFormatFlags.EndEllipsis);
        }

        /// <summary>
        /// Стрелка ветки простым треугольником — для систем, где нет шрифта со значками
        /// (старые версии Windows, серверы без оформления): без неё ветку было бы нечем свернуть мышью.
        /// </summary>
        private static void DrawPlainArrow(Graphics g, Rectangle area, bool open)
        {
            int half = Ui.S(4);
            int x = area.X + area.Width / 2;
            int y = area.Y + area.Height / 2;
            Point[] points = open
                ? new[] { new Point(x - half, y - half / 2), new Point(x + half, y - half / 2), new Point(x, y + half / 2 + 1) }
                : new[] { new Point(x - half / 2, y - half), new Point(x + half / 2 + 1, y), new Point(x - half / 2, y + half) };

            System.Drawing.Drawing2D.SmoothingMode previous = g.SmoothingMode;
            g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
            using (var brush = new SolidBrush(Ui.Muted))
            {
                g.FillPolygon(brush, points);
            }
            g.SmoothingMode = previous;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (Bitmap bitmap in new[] { iconAll, iconGroup, iconNone, iconTrash, arrowClosed, arrowOpen })
                {
                    if (bitmap != null) bitmap.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>Таблица записей: без мерцания, с оформлением как в Проводнике и стрелкой сортировки.</summary>
    internal sealed class EntryListView : ListView
    {
        public EntryListView()
        {
            DoubleBuffered = true;
            View = View.Details;
            FullRowSelect = true;
            HideSelection = false;
            MultiSelect = true;
            ShowItemToolTips = true;
            BorderStyle = BorderStyle.None;
            HeaderStyle = ColumnHeaderStyle.Clickable;
            Font = Ui.Font;
        }

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            NativeMethods.SetWindowTheme(Handle, "explorer", null);
        }

        /// <summary>Высота строки заголовков столбцов в пикселях (0, пока окно не создано).</summary>
        public int HeaderHeight
        {
            get
            {
                if (!IsHandleCreated) return 0;
                IntPtr header = NativeMethods.SendMessage(Handle, NativeMethods.LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);
                NativeMethods.RECT bounds;
                if (header == IntPtr.Zero || !NativeMethods.GetWindowRect(header, out bounds)) return 0;
                return bounds.Bottom - bounds.Top;
            }
        }

        /// <summary>Показывает стрелку сортировки в заголовке столбца.</summary>
        public void SetSortArrow(int column, bool ascending)
        {
            if (!IsHandleCreated) return;
            IntPtr header = NativeMethods.SendMessage(Handle, NativeMethods.LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);
            if (header == IntPtr.Zero) return;

            for (int i = 0; i < Columns.Count; i++)
            {
                var item = new NativeMethods.HDITEM();
                item.mask = NativeMethods.HDI_FORMAT;
                NativeMethods.SendMessage(header, NativeMethods.HDM_GETITEM, (IntPtr)i, ref item);
                item.fmt &= ~(NativeMethods.HDF_SORTUP | NativeMethods.HDF_SORTDOWN);
                if (i == column)
                {
                    item.fmt |= ascending ? NativeMethods.HDF_SORTUP : NativeMethods.HDF_SORTDOWN;
                }
                NativeMethods.SendMessage(header, NativeMethods.HDM_SETITEM, (IntPtr)i, ref item);
            }
        }
    }

    /// <summary>Надпись поверх списка, которая не перехватывает щелчки мыши.</summary>
    internal sealed class PassThroughLabel : Label
    {
        protected override void WndProc(ref Message m)
        {
            if (m.Msg == NativeMethods.WM_NCHITTEST)
            {
                m.Result = (IntPtr)NativeMethods.HTTRANSPARENT;
                return;
            }
            base.WndProc(ref m);
        }
    }

    /// <summary>Разделитель между списком групп и записями: тонкая линия, за которую можно тянуть.</summary>
    internal sealed class LineSplitter : Splitter
    {
        public LineSplitter()
        {
            SetStyle(ControlStyles.ResizeRedraw, true);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            using (var pen = new Pen(Ui.Line))
            {
                e.Graphics.DrawLine(pen, Width - 1, 0, Width - 1, Height);
            }
        }
    }

    /// <summary>Следит за вводом в окнах программы — для автоблокировки по бездействию.</summary>
    internal sealed class IdleMonitor : IMessageFilter
    {
        private int lastActivity = Environment.TickCount;

        public int IdleSeconds
        {
            get { return unchecked(Environment.TickCount - lastActivity) / 1000; }
        }

        public void Reset()
        {
            lastActivity = Environment.TickCount;
        }

        public bool PreFilterMessage(ref Message m)
        {
            int msg = m.Msg;
            bool keyboard = msg >= 0x0100 && msg <= 0x0109;   // WM_KEYDOWN … WM_UNICHAR
            bool mouse = msg >= 0x0200 && msg <= 0x020E;      // WM_MOUSEMOVE … WM_MOUSEHWHEEL
            if (keyboard || mouse)
            {
                lastActivity = Environment.TickCount;
            }
            return false;
        }
    }
}
