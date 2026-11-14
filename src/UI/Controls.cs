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

    /// <summary>Строка в списке групп: «Все записи», обычная группа или «Без группы».</summary>
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
                default:
                    return GroupFilter.All;
            }
        }

        public override string ToString()
        {
            return Name;
        }
    }

    /// <summary>Список групп слева: значок, название, число записей, подсветка при перетаскивании.</summary>
    internal sealed class GroupListBox : ListBox
    {
        private readonly Bitmap iconAll;
        private readonly Bitmap iconGroup;
        private readonly Bitmap iconNone;
        private int dropIndex = -1;

        public GroupListBox()
        {
            DrawMode = DrawMode.OwnerDrawFixed;
            IntegralHeight = false;
            BorderStyle = BorderStyle.None;
            ItemHeight = Math.Min(255, Ui.S(30));
            BackColor = Ui.PaneBack;
            ForeColor = Ui.TextColor;
            Font = Ui.Font;

            iconAll = Ui.Glyph(Ui.GlyphList, 16, Ui.GlyphColor);
            iconGroup = Ui.Glyph(Ui.GlyphFolder, 16, Ui.GlyphColor);
            iconNone = Ui.Glyph(Ui.GlyphPage, 16, Ui.Muted);
        }

        /// <summary>Строка, над которой сейчас находятся перетаскиваемые записи; -1 — нет такой.</summary>
        public int DropIndex
        {
            get { return dropIndex; }
            set
            {
                if (dropIndex == value) return;
                int old = dropIndex;
                dropIndex = value;
                InvalidateItem(old);
                InvalidateItem(value);
            }
        }

        private void InvalidateItem(int index)
        {
            if (index >= 0 && index < Items.Count && IsHandleCreated)
            {
                Invalidate(GetItemRectangle(index));
            }
        }

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            if (e.Index < 0 || e.Index >= Items.Count) return;

            var item = (GroupItem)Items[e.Index];
            bool selected = (e.State & DrawItemState.Selected) == DrawItemState.Selected;
            bool drop = e.Index == dropIndex;
            Rectangle bounds = e.Bounds;
            Graphics g = e.Graphics;

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

            Color textColor = (selected || drop) ? Ui.SelectedText : (item.Kind == FilterKind.Ungrouped ? Ui.Muted : ForeColor);
            Color countColor = (selected || drop) ? Ui.SelectedText : Ui.Muted;

            int x = bounds.X + Ui.S(14);
            Bitmap icon = item.Kind == FilterKind.All ? iconAll : (item.Kind == FilterKind.Group ? iconGroup : iconNone);
            if (icon != null)
            {
                g.DrawImage(icon, x, bounds.Y + (bounds.Height - icon.Height) / 2, icon.Width, icon.Height);
                x += icon.Width + Ui.S(9);
            }

            const TextFormatFlags flags = TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding;

            string count = item.Count.ToString();
            Size countSize = TextRenderer.MeasureText(g, count, Font, Size.Empty, flags);
            var countBounds = new Rectangle(bounds.Right - Ui.S(12) - countSize.Width, bounds.Y, countSize.Width, bounds.Height);
            TextRenderer.DrawText(g, count, Font, countBounds, countColor, flags);

            var textBounds = new Rectangle(x, bounds.Y, Math.Max(0, countBounds.X - Ui.S(8) - x), bounds.Height);
            TextRenderer.DrawText(g, item.Name, Font, textBounds, textColor, flags | TextFormatFlags.EndEllipsis);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (iconAll != null) iconAll.Dispose();
                if (iconGroup != null) iconGroup.Dispose();
                if (iconNone != null) iconNone.Dispose();
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
