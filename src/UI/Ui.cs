using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Drawing.Text;
using System.IO;
using System.Windows.Forms;

namespace KeyBox.UI
{
    /// <summary>Общее для всех окон: масштаб экрана, шрифты, цвета, значки, мелкие помощники.</summary>
    internal static class Ui
    {
        // Значки берутся из системного шрифта: в Windows 11 это Segoe Fluent Icons,
        // в Windows 10 — Segoe MDL2 Assets (коды символов у них общие).
        // Если нет ни того, ни другого, кнопки остаются с текстом.
        private static readonly string[] GlyphFontNames = { "Segoe Fluent Icons", "Segoe MDL2 Assets" };
        private static readonly string GlyphFontName;

        public const int GlyphAdd = 0xE710;
        public const int GlyphEdit = 0xE70F;
        public const int GlyphDelete = 0xE74D;
        public const int GlyphCopy = 0xE8C8;
        public const int GlyphEye = 0xE7B3;
        public const int GlyphLock = 0xE72E;
        public const int GlyphMore = 0xE712;
        public const int GlyphFolder = 0xE8B7;
        public const int GlyphMove = 0xE8DE;
        public const int GlyphList = 0xE8FD;
        public const int GlyphPage = 0xE7C3;
        public const int GlyphRename = 0xE8AC;
        public const int GlyphInfo = 0xE946;
        public const int GlyphWarning = 0xE7BA;
        public const int GlyphError = 0xEA39;
        public const int GlyphQuestion = 0xE9CE;
        public const int GlyphChevronRight = 0xE76C;
        public const int GlyphChevronDown = 0xE70D;
        public const int GlyphKeyboard = 0xE765;
        public const int GlyphSettings = 0xE713;
        public const int GlyphRecycle = 0xE74D;
        public const int GlyphHistory = 0xE81C;
        public const int GlyphUndo = 0xE7A7;

        /// <summary>Масштаб экрана: 1.0 при 100 %, 1.5 при 150 % и т. д.</summary>
        public static readonly float Scale;

        public static readonly Font Font;
        public static readonly Font BoldFont;
        public static readonly Font SmallFont;
        public static readonly Font TitleFont;
        public static readonly Font MonoFont;
        public static readonly Font GlyphFont;
        public static readonly bool HasGlyphs;

        public static readonly Color Accent;
        public static readonly Color SelectedBack;
        public static readonly Color SelectedText;
        public static readonly Color DropBack;
        public static readonly Color HoverBack;
        public static readonly Color HoverBorder;
        public static readonly Color PressedBack;
        public static readonly Color PaneBack;
        public static readonly Color Line;
        public static readonly Color TextColor;
        public static readonly Color Muted;
        public static readonly Color Danger;
        public static readonly Color Success;
        public static readonly Color GlyphColor;

        public static readonly ToolStripRenderer Renderer;

        /// <summary>Режим автоматических тестов: окна показываются, не перехватывая фокус.</summary>
        public static bool NoActivate { get; set; }

        /// <summary>Режим автоматических тестов: все окна открываются в этой точке (обычно за краем экрана).</summary>
        public static Point? TestOrigin { get; set; }

        private static Icon appIcon;
        private static bool appIconLoaded;

        static Ui()
        {
            using (Graphics g = Graphics.FromHwnd(IntPtr.Zero))
            {
                Scale = g.DpiX / 96f;
            }

            Font = SystemFonts.MessageBoxFont ?? Control.DefaultFont;
            BoldFont = new Font(Font, FontStyle.Bold);
            SmallFont = new Font(Font.FontFamily, Math.Max(7.5f, Font.SizeInPoints - 0.75f));
            TitleFont = TryFont("Segoe UI Semibold", 15f, new Font(Font.FontFamily, 15f, FontStyle.Bold));
            MonoFont = TryFont("Consolas", Font.SizeInPoints + 0.5f, new Font(FontFamily.GenericMonospace, Font.SizeInPoints));

            foreach (string name in GlyphFontNames)
            {
                Font glyphs = TryFont(name, 10.5f, null);
                if (glyphs != null)
                {
                    GlyphFontName = name;
                    GlyphFont = glyphs;
                    HasGlyphs = true;
                    break;
                }
            }

            if (SystemInformation.HighContrast)
            {
                // В режиме высокой контрастности используем только системные цвета.
                Accent = SystemColors.Highlight;
                SelectedBack = SystemColors.Highlight;
                SelectedText = SystemColors.HighlightText;
                DropBack = SystemColors.Highlight;
                HoverBack = SystemColors.Highlight;
                HoverBorder = SystemColors.HighlightText;
                PressedBack = SystemColors.Highlight;
                PaneBack = SystemColors.Window;
                Line = SystemColors.WindowFrame;
                TextColor = SystemColors.WindowText;
                Muted = SystemColors.GrayText;
                Danger = SystemColors.WindowText;
                Success = SystemColors.WindowText;
                GlyphColor = SystemColors.WindowText;
                Renderer = new ToolStripSystemRenderer();
            }
            else
            {
                Accent = Color.FromArgb(37, 99, 235);
                SelectedBack = Color.FromArgb(219, 234, 254);
                SelectedText = Color.FromArgb(17, 24, 39);
                DropBack = Color.FromArgb(191, 219, 254);
                HoverBack = Color.FromArgb(233, 240, 250);
                HoverBorder = Color.FromArgb(200, 218, 243);
                PressedBack = Color.FromArgb(212, 226, 247);
                PaneBack = Color.FromArgb(244, 245, 247);
                Line = Color.FromArgb(225, 228, 233);
                TextColor = Color.FromArgb(17, 24, 39);
                Muted = Color.FromArgb(107, 114, 128);
                Danger = Color.FromArgb(185, 28, 28);
                Success = Color.FromArgb(21, 128, 61);
                GlyphColor = Color.FromArgb(55, 65, 81);
                Renderer = new FlatRenderer();
            }
            ToolStripManager.Renderer = Renderer;
        }

        /// <summary>Переводит размер в пикселях для 100 % в пиксели текущего масштаба экрана.</summary>
        public static int S(int pixels)
        {
            return (int)Math.Round(pixels * Scale);
        }

        // ---------- Значки ----------

        /// <summary>Значок программы (из встроенного ресурса) или null.</summary>
        public static Icon AppIcon
        {
            get
            {
                if (!appIconLoaded)
                {
                    appIconLoaded = true;
                    try
                    {
                        using (Stream stream = typeof(Ui).Assembly.GetManifestResourceStream("KeyBox.app.ico"))
                        {
                            if (stream != null) appIcon = new Icon(stream);
                        }
                    }
                    catch (ArgumentException) { }
                    catch (IOException) { }
                }
                return appIcon;
            }
        }

        /// <summary>Логотип нужного размера (в пикселях для 100 %) или null, если ресурса нет.</summary>
        public static Bitmap Logo(int size)
        {
            int px = S(size);
            try
            {
                using (Stream stream = typeof(Ui).Assembly.GetManifestResourceStream("KeyBox.logo.png"))
                {
                    if (stream == null) return null;
                    using (var source = new Bitmap(stream))
                    using (var attributes = new ImageAttributes())
                    {
                        attributes.SetWrapMode(WrapMode.TileFlipXY);
                        var result = new Bitmap(px, px, PixelFormat.Format32bppArgb);
                        using (Graphics g = Graphics.FromImage(result))
                        {
                            g.InterpolationMode = InterpolationMode.HighQualityBicubic;
                            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                            g.DrawImage(source, new Rectangle(0, 0, px, px), 0, 0, source.Width, source.Height, GraphicsUnit.Pixel, attributes);
                        }
                        return result;
                    }
                }
            }
            catch (ArgumentException)
            {
                return null;
            }
        }

        /// <summary>Рисует значок из шрифта Segoe MDL2 Assets. Возвращает null, если шрифта нет.</summary>
        public static Bitmap Glyph(int code, int size, Color color)
        {
            if (!HasGlyphs) return null;

            int px = S(size);
            var bitmap = new Bitmap(px, px, PixelFormat.Format32bppArgb);
            using (Graphics g = Graphics.FromImage(bitmap))
            using (var font = new Font(GlyphFontName, px, FontStyle.Regular, GraphicsUnit.Pixel))
            using (var brush = new SolidBrush(color))
            using (var format = new StringFormat(StringFormat.GenericTypographic))
            {
                g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
                format.Alignment = StringAlignment.Center;
                format.LineAlignment = StringAlignment.Center;
                // Рисуем относительно центральной точки, а не в прямоугольнике: при некоторых
                // размерах высота строки на долю пикселя превышает прямоугольник, и тогда
                // GDI+ не выводит строку вовсе — значок получался бы пустым.
                g.DrawString(GlyphText(code), font, brush, new PointF(px / 2f, px / 2f), format);
            }
            return bitmap;
        }

        public static string GlyphText(int code)
        {
            return ((char)code).ToString();
        }

        // ---------- Элементы управления ----------

        public static Button MakeButton(string text)
        {
            var button = new Button();
            button.Text = text;
            button.AutoSize = true;
            button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            button.MinimumSize = new Size(S(92), S(28));
            button.Padding = new Padding(S(8), 0, S(8), 0);
            button.Margin = new Padding(S(8), 0, 0, 0);
            button.UseVisualStyleBackColor = true;
            return button;
        }

        public static Label MakeLabel(string text)
        {
            var label = new Label();
            label.Text = text;
            label.AutoSize = true;
            label.UseMnemonic = false;
            label.Margin = Padding.Empty;
            return label;
        }

        /// <summary>Подпись, которая переносится по словам в пределах заданной ширины.</summary>
        public static Label MakeWrapLabel(string text, int width, Color color)
        {
            Label label = MakeLabel(text);
            label.MaximumSize = new Size(width, 0);
            label.ForeColor = color;
            return label;
        }

        /// <summary>Строка для сообщения об ошибке под полями ввода; пока текста нет — скрыта.</summary>
        public static Label MakeErrorLabel(int width)
        {
            Label label = MakeWrapLabel("", width, Danger);
            label.Name = "lblError";
            label.Visible = false;
            label.Margin = new Padding(0, S(8), 0, 0);
            return label;
        }

        public static void ShowError(Label label, string message)
        {
            label.Text = message ?? "";
            label.Visible = !string.IsNullOrEmpty(message);
        }

        /// <summary>Кнопка-переключатель «показать пароль» со значком глаза.</summary>
        public static CheckBox MakeEyeToggle(int height)
        {
            var toggle = new CheckBox();
            toggle.Appearance = Appearance.Button;
            toggle.TextAlign = ContentAlignment.MiddleCenter;
            toggle.UseVisualStyleBackColor = true;
            toggle.Margin = new Padding(S(6), 0, 0, 0);
            toggle.AccessibleName = L.T("Показать пароль", "Show password");
            if (HasGlyphs)
            {
                toggle.Font = GlyphFont;
                toggle.Text = GlyphText(GlyphEye);
                toggle.AutoSize = false;
                toggle.Size = new Size(S(32), height);
            }
            else
            {
                toggle.Text = L.T("Показать", "Show");
                toggle.AutoSize = true;
            }
            return toggle;
        }

        // ---------- Сайты ----------

        /// <summary>Нужен тестам: вместо запуска браузера адрес передаётся сюда.</summary>
        internal static Func<string, bool> UrlLauncher { get; set; }

        /// <summary>
        /// Приводит адрес сайта из записи к виду, который можно открыть в браузере:
        /// «example.com» превращается в «https://example.com/». Возвращает null, если это не адрес сайта.
        /// Открываются только адреса http и https: адрес берётся из данных (в том числе
        /// импортированных из чужого файла), и запускать по нему что-либо другое нельзя.
        /// </summary>
        public static string NormalizeUrl(string url)
        {
            string value = (url ?? "").Trim();
            if (value.Length == 0 || value.IndexOfAny(new[] { ' ', '\t', '\r', '\n', '"', '\\' }) >= 0) return null;
            if (value.IndexOf("://", StringComparison.Ordinal) < 0)
            {
                // Без «https://» допустим только вид «сайт[:порт][/путь]». Строки вроде «mailto:…»
                // или «javascript:…» и адреса почты — не сайты.
                int slash = value.IndexOf('/');
                string authority = slash < 0 ? value : value.Substring(0, slash);
                if (authority.IndexOf('@') >= 0) return null;
                int colon = authority.IndexOf(':');
                if (colon >= 0)
                {
                    string port = authority.Substring(colon + 1);
                    if (port.Length == 0) return null;
                    foreach (char c in port)
                    {
                        if (c < '0' || c > '9') return null;
                    }
                }
                value = "https://" + value;
            }

            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri)) return null;
            if (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps) return null;
            if (string.IsNullOrEmpty(uri.Host)) return null;
            return uri.AbsoluteUri;
        }

        /// <summary>Открывает адрес сайта в браузере по умолчанию. Возвращает false, если это не удалось.</summary>
        public static bool OpenUrl(string url)
        {
            string target = NormalizeUrl(url);
            if (target == null) return false;
            if (UrlLauncher != null) return UrlLauncher(target);

            try
            {
                var start = new System.Diagnostics.ProcessStartInfo(target);
                start.UseShellExecute = true;
                using (System.Diagnostics.Process.Start(start))
                {
                }
                return true;
            }
            catch (System.ComponentModel.Win32Exception) { return false; }
            catch (InvalidOperationException) { return false; }
            catch (IOException) { return false; }
        }

        // ---------- Файлы ----------

        /// <summary>
        /// Нужен тестам: вместо окна выбора файла путь берётся отсюда. Первый параметр — true для
        /// сохранения, второй — предложенное имя файла; null в ответ означает «отмена».
        /// </summary>
        internal static Func<bool, string, string> FilePicker { get; set; }

        /// <summary>Спрашивает у пользователя файл — для открытия или для сохранения. Возвращает путь или null.</summary>
        public static string PickFile(IWin32Window owner, bool save, string title, string filter, string suggestedName)
        {
            if (FilePicker != null) return FilePicker(save, suggestedName);

            if (save)
            {
                using (var dialog = new SaveFileDialog())
                {
                    dialog.Title = title;
                    dialog.Filter = filter;
                    dialog.FileName = suggestedName ?? "";
                    dialog.OverwritePrompt = true;
                    return dialog.ShowDialog(owner) == DialogResult.OK ? dialog.FileName : null;
                }
            }
            using (var dialog = new OpenFileDialog())
            {
                dialog.Title = title;
                dialog.Filter = filter;
                dialog.CheckFileExists = true;
                return dialog.ShowDialog(owner) == DialogResult.OK ? dialog.FileName : null;
            }
        }

        // ---------- Текст ----------

        /// <summary>Сравнение строк «как в Проводнике»: без учёта регистра, числа — по значению.</summary>
        public static int CompareNatural(string a, string b)
        {
            return NativeMethods.StrCmpLogicalW(a ?? "", b ?? "");
        }

        /// <summary>Многострочный текст одной строкой — для списка.</summary>
        public static string SingleLine(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            string line = text.Replace("\r\n", " ").Replace('\n', ' ').Replace('\r', ' ').Replace('\t', ' ');
            return line.Length > 400 ? line.Substring(0, 400) + "…" : line;
        }

        public static string Shorten(string text, int maxLength)
        {
            string line = SingleLine(text);
            return line.Length > maxLength ? line.Substring(0, maxLength - 1) + "…" : line;
        }

        /// <summary>Текст для пункта меню: «&amp;» не должен превращаться в подчёркивание.</summary>
        public static string MenuText(string text)
        {
            return Shorten(text, 60).Replace("&", "&&");
        }

        /// <summary>
        /// Сокращает путь так, чтобы он уместился в заданную ширину: середина заменяется
        /// многоточием, а диск и имя файла остаются на виду — «C:\…\папка\keybox.vault».
        /// </summary>
        public static string FitPath(string path, Font font, int maxWidth)
        {
            if (string.IsNullOrEmpty(path)) return "";
            if (TextWidth(path, font) <= maxWidth) return path;

            string separator = Path.DirectorySeparatorChar.ToString();
            string root = Path.GetPathRoot(path) ?? "";
            string[] parts = path.Substring(root.Length).Split(
                new[] { Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0) return path;

            for (int keep = parts.Length - 1; keep >= 1; keep--)
            {
                string candidate = root + "…" + separator + string.Join(separator, parts, parts.Length - keep, keep);
                if (TextWidth(candidate, font) <= maxWidth) return candidate;
            }
            return "…" + separator + parts[parts.Length - 1];
        }

        private static int TextWidth(string text, Font font)
        {
            return TextRenderer.MeasureText(text, font, Size.Empty, TextFormatFlags.NoPrefix | TextFormatFlags.SingleLine).Width;
        }

        private static Font TryFont(string family, float size, Font fallback)
        {
            try
            {
                var font = new Font(family, size);
                if (string.Equals(font.Name, family, StringComparison.OrdinalIgnoreCase)) return font;
                font.Dispose();
            }
            catch (ArgumentException) { }
            return fallback;
        }
    }
}
