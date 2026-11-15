using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using KeyBox.UI;
using KeyBox.Vault;
using FormsTimer = System.Windows.Forms.Timer;

namespace KeyBox.Tests
{
    /// <summary>
    /// Сквозная проверка интерфейса. Тест запускает настоящие окна программы внутри
    /// своего процесса и работает с ними как пользователь: нажимает кнопки, заполняет
    /// поля, отвечает на вопросы. Окна открываются за краем экрана и не перехватывают
    /// фокус, поэтому прогон не мешает работе за компьютером.
    ///
    ///   UiTests.exe &lt;рабочая папка&gt; [--visible] [--scale 1.5]
    ///
    /// В рабочей папке создаётся тестовое хранилище, в подпапке shots — снимки окон.
    /// С ключом --visible окна показываются на экране (для снимков «как есть»),
    /// ключ --scale имитирует масштаб экрана 150 %, 200 % и т. п.
    /// </summary>
    internal static class UiTests
    {
        private const string MasterPassword = "верный мастер-пароль";
        private const string NewMasterPassword = "совсем другой пароль 2";
        private const string EnglishVaultName = "english.vault";

        private static readonly string Mask = new string((char)0x2022, 8);
        private static readonly HashSet<Form> driven = new HashSet<Form>();

        private static string workDir;
        private static string shotDir;
        private static string vaultPath;
        private static bool visible;
        private static int passed;
        private static int failed;
        private static int skipped;
        private static Exception asyncFailure;

        private static VaultSession session;
        private static MainForm main;

        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = new UTF8Encoding(false);
            }
            catch (IOException)
            {
                // нет консоли (режим --clipboard-child) — вывод всё равно уйдёт в файл отчёта
            }
            if (args.Length == 0)
            {
                Console.WriteLine("usage: UiTests <work-dir> [--visible]");
                return 2;
            }

            // Сценарий сверяет русские тексты окон, поэтому язык задаётся явно, а не берётся из системы.
            L.Current = Language.Russian;

            workDir = Path.GetFullPath(args[0]);
            Directory.CreateDirectory(workDir);
            visible = Array.IndexOf(args, "--visible") >= 0;
            bool clipboardChild = Array.IndexOf(args, "--clipboard-child") >= 0;

            // Страховка: зависший диалог не должен подвесить прогон навсегда.
            var watchdog = new Thread(delegate()
            {
                Thread.Sleep(240000);
                Console.WriteLine("TIMEOUT: the UI test run did not finish in time");
                Environment.Exit(3);
            });
            watchdog.IsBackground = true;
            watchdog.Start();

            if (clipboardChild)
            {
                return ClipboardChild();
            }

            // Проверка буфера обмена идёт в отдельном процессе на изолированной оконной станции.
            // Запускаем её первой, пока у этого процесса ещё нет ни одного окна.
            ClipboardInIsolation();

            float scale = 1f;
            int scaleIndex = Array.IndexOf(args, "--scale");
            if (scaleIndex >= 0 && scaleIndex + 1 < args.Length)
            {
                scale = float.Parse(args[scaleIndex + 1], System.Globalization.CultureInfo.InvariantCulture);
            }

            bool noIcons = Array.IndexOf(args, "--no-icons") >= 0;
            shotDir = Path.Combine(workDir, visible ? "shots-visible" : (noIcons ? "shots-no-icons" : (scale == 1f ? "shots" : "shots-" + (int)(scale * 100))));
            Directory.CreateDirectory(shotDir);
            vaultPath = Path.Combine(workDir, "keybox.vault");
            CleanUp();

            InitializeForms();
            if (scale != 1f) SimulateScale(scale);
            if (noIcons) SimulateMissingIconFont();
            Ui.NoActivate = true;
            if (!visible) Ui.TestOrigin = new Point(-30000, -30000);
            Console.WriteLine("screen scale: {0:P0}, glyph font: {1}", Ui.Scale, Ui.HasGlyphs ? "yes" : "no");

            Run("icons are drawn at every size", IconsAtEverySize);
            Run("create a vault: validation, then creation", CreateVault);
            Run("main window of an empty vault", EmptyMainWindow);
            Run("groups: create, validate, order", CreateGroups);
            Run("entries: create, validate, generate a password", CreateEntries);
            Run("groups: filter and counters", FilterByGroup);
            Run("entries: edit, including the group", EditEntry);
            Run("move between groups: the 'to group' menu", MoveByMenu);
            Run("move between groups: drag and drop", MoveByDragDrop);
            Run("search", Search);
            Run("show passwords and sorting", ShowPasswordsAndSort);
            Run("keyboard shortcuts", Shortcuts);
            Run("entries: delete with confirmation", DeleteEntry);
            Run("groups: rename and delete", RenameAndDeleteGroup);
            Run("long texts do not break the layout", LongTexts);
            Run("nested groups: subgroups, paths, moving and deleting branches", NestedGroups);
            Run("about box", About);
            Run("failed save is reported and can be retried", SaveFailure);
            Run("every change is already on disk", Persistence);
            Run("lock closes the window", Lock);
            Run("unlock: wrong password, then the right one", Unlock);
            Run("change the master password", ChangeMasterPassword);
            Run("auto-lock also closes open dialogs", AutoLock);
            Run("english interface: every window, nothing left untranslated", EnglishInterface);

            if (main != null && !main.IsDisposed) main.Close();
            if (session != null) session.Dispose();

            Console.WriteLine();
            Console.WriteLine("{0} passed, {1} failed{2}", passed, failed, skipped > 0 ? ", " + skipped + " skipped" : "");
            Console.WriteLine("screenshots: " + shotDir);
            return failed == 0 ? 0 : 1;
        }

        /// <summary>
        /// Имитация крупного масштаба экрана (150 %, 200 %) на обычном мониторе: подменяет
        /// коэффициент масштаба и шрифты программы до создания первого окна. Системные элементы
        /// (заголовок окна, полосы прокрутки) остаются прежнего размера, но раскладка содержимого
        /// ведёт себя так же, как при настоящем масштабе.
        /// </summary>
        private static void SimulateScale(float scale)
        {
            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(Ui).TypeHandle);
            foreach (string name in new[] { "Font", "BoldFont", "SmallFont", "TitleFont", "MonoFont", "GlyphFont" })
            {
                FieldInfo field = typeof(Ui).GetField(name, BindingFlags.Static | BindingFlags.Public);
                var font = (Font)field.GetValue(null);
                if (font != null) field.SetValue(null, new Font(font.FontFamily, font.SizeInPoints * scale, font.Style));
            }
            typeof(Ui).GetField("Scale", BindingFlags.Static | BindingFlags.Public).SetValue(null, Ui.Scale * scale);
        }

        /// <summary>
        /// Имитация системы без шрифта со значками (старые версии Windows, часть серверов):
        /// кнопки должны остаться с текстом, а всё остальное — работать как обычно.
        /// </summary>
        private static void SimulateMissingIconFont()
        {
            System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(typeof(Ui).TypeHandle);
            typeof(Ui).GetField("HasGlyphs", BindingFlags.Static | BindingFlags.Public).SetValue(null, false);
            typeof(Ui).GetField("GlyphFont", BindingFlags.Static | BindingFlags.Public).SetValue(null, null);
        }

        private static void InitializeForms()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
            Application.ThreadException += delegate(object s, ThreadExceptionEventArgs e) { asyncFailure = e.Exception; };
        }

        private static void CleanUp()
        {
            foreach (string file in new[] { vaultPath, vaultPath + ".bak", vaultPath + ".tmp" })
            {
                if (Directory.Exists(file)) Directory.Delete(file, true);
                if (File.Exists(file)) File.Delete(file);
            }
        }

        // =====================================================================
        //  Буфер обмена — на изолированной оконной станции
        // =====================================================================

        /// <summary>Запускает этот же тест в режиме --clipboard-child на отдельной оконной станции.</summary>
        private static void ClipboardInIsolation()
        {
            string report = Path.Combine(workDir, "clipboard-report.txt");
            if (File.Exists(report)) File.Delete(report);

            string exe = Assembly.GetExecutingAssembly().Location;
            string command = "\"" + exe + "\" \"" + workDir + "\" --clipboard-child";
            try
            {
                int exitCode = IsolatedDesktop.Run(command, 120000);
                string[] lines = File.Exists(report) ? File.ReadAllLines(report, Encoding.UTF8) : new string[0];
                foreach (string line in lines)
                {
                    Console.WriteLine(line);
                    if (line.StartsWith("ok ")) passed++;
                    if (line.StartsWith("FAIL")) failed++;
                }
                if (exitCode != 0 && lines.Length == 0)
                {
                    failed++;
                    Console.WriteLine("FAIL  clipboard checks: the isolated process exited with code " + exitCode + " and left no report");
                }
            }
            catch (Exception ex)
            {
                // Нет прав на создание оконной станции и т. п. Свой буфер обмена ради теста не трогаем.
                skipped++;
                Console.WriteLine("skip  clipboard checks: no isolated desktop (" + ex.GetType().Name + ": " + ex.Message + ")");
            }
        }

        /// <summary>
        /// Работает внутри изолированной оконной станции: там свой, пустой буфер обмена.
        /// Модальные окна на такой станции Windows Forms показывать не разрешает, поэтому
        /// данные готовятся напрямую, а в окне нажимаются только кнопки копирования.
        /// </summary>
        private static int ClipboardChild()
        {
            using (var report = new StreamWriter(Path.Combine(workDir, "clipboard-report.txt"), false, new UTF8Encoding(false)))
            {
                report.AutoFlush = true;
                Console.SetOut(report);
                try
                {
                    InitializeForms();
                    Ui.NoActivate = true;

                    vaultPath = Path.Combine(workDir, "clipboard-test.vault");
                    CleanUp();
                    session = VaultSession.Create(vaultPath, MasterPassword, VaultFormat.MinIterations);
                    session.Data.AddEntry(null, "ivan.petrov@example.com", "Qw7!kPz#2026mail", "Почта Gmail");
                    session.Data.AddEntry(null, "nopass", "", "Без пароля");
                    session.Save();

                    main = new MainForm(session);
                    main.Show();
                    Pump(200);

                    Run("clipboard: copy with the toolbar and with Ctrl+C / Ctrl+B", ClipboardCopy);
                    Run("clipboard: kept out of the clipboard history and the cloud", ClipboardExclusion);
                    Run("clipboard: cleared on demand and by the timer", ClipboardClearing);
                    Run("clipboard: foreign content is never cleared", ClipboardForeignContent);
                    Run("clipboard: an empty password is not copied", ClipboardEmptyPassword);

                    main.Close();
                    session.Dispose();
                    CleanUp();
                }
                catch (Exception ex)
                {
                    failed++;
                    Console.WriteLine("FAIL  clipboard checks could not start");
                    Console.WriteLine("      " + ex.GetType().Name + ": " + ex.Message);
                }
                return failed == 0 ? 0 : 1;
            }
        }

        // =====================================================================
        //  Сценарии
        // =====================================================================

        /// <summary>
        /// Значки рисуются из системного шрифта в картинку нужного размера. При масштабе экрана
        /// 125–200 % размеры получаются самые разные, и ни при одном значок не должен выйти
        /// пустым или съехать из центра.
        /// </summary>
        private static void IconsAtEverySize()
        {
            if (!Ui.HasGlyphs)
            {
                Console.WriteLine("      no icon font on this system: buttons fall back to text");
                return;
            }

            int[] glyphs =
            {
                Ui.GlyphAdd, Ui.GlyphEdit, Ui.GlyphDelete, Ui.GlyphCopy, Ui.GlyphEye, Ui.GlyphLock, Ui.GlyphMore,
                Ui.GlyphFolder, Ui.GlyphMove, Ui.GlyphList, Ui.GlyphPage, Ui.GlyphRename,
                Ui.GlyphInfo, Ui.GlyphWarning, Ui.GlyphError, Ui.GlyphQuestion,
                Ui.GlyphChevronRight, Ui.GlyphChevronDown
            };

            foreach (int glyph in glyphs)
            {
                for (int size = 10; size <= 72; size++)
                {
                    using (Bitmap bitmap = Ui.Glyph(glyph, size, Color.Black))
                    {
                        int left = int.MaxValue, top = int.MaxValue, right = -1, bottom = -1;
                        for (int y = 0; y < bitmap.Height; y++)
                        {
                            for (int x = 0; x < bitmap.Width; x++)
                            {
                                if (bitmap.GetPixel(x, y).A < 40) continue;
                                if (x < left) left = x;
                                if (x > right) right = x;
                                if (y < top) top = y;
                                if (y > bottom) bottom = y;
                            }
                        }

                        string what = string.Format("glyph {0:X4} at {1} px", glyph, bitmap.Width);
                        Check(right >= 0, what + " is blank");

                        // Рисунок занимает заметную часть картинки и стоит примерно по центру.
                        double centerX = (left + right + 1) / 2.0 / bitmap.Width;
                        double centerY = (top + bottom + 1) / 2.0 / bitmap.Height;
                        Check(right - left + 1 >= bitmap.Width / 3 || bottom - top + 1 >= bitmap.Height / 3, what + " is too small");
                        Check(centerX > 0.3 && centerX < 0.7 && centerY > 0.3 && centerY < 0.7,
                            string.Format("{0} is off-centre ({1:F2}, {2:F2})", what, centerX, centerY));
                    }
                }
            }
        }

        private static void CreateVault()
        {
            using (var form = new UnlockForm(vaultPath))
            {
                Check(form.CreateMode, "create mode when there is no file yet");
                DialogResult result = DialogResult.None;

                Drive<UnlockForm>(delegate { result = form.ShowDialog(); }, delegate(UnlockForm f)
                {
                    TextBox password = Find<TextBox>(f, "txtPassword");
                    TextBox confirm = Find<TextBox>(f, "txtConfirm");
                    Label error = Find<Label>(f, "lblError");
                    Label hint = Find<Label>(f, "lblHint");
                    CheckBox show = Find<CheckBox>(f, "chkShow");

                    Check(password.UseSystemPasswordChar && confirm.UseSystemPasswordChar, "passwords are masked");
                    Check(!error.Visible, "no error at the start");
                    Check(Find<Button>(f, "btnOk").Text == "Создать хранилище", "button caption");

                    // Пустой и слишком короткий пароль.
                    Click(f, "btnOk");
                    Check(error.Visible && error.Text.Contains("Введите"), "empty password: " + error.Text);
                    password.Text = "абв";
                    confirm.Text = "абв";
                    Check(!error.Visible, "typing clears the error");
                    Check(hint.Text.Contains("короткий"), "hint for a short password: " + hint.Text);
                    Click(f, "btnOk");
                    Check(error.Visible && error.Text.Contains("не короче"), "short password is rejected: " + error.Text);
                    Shot(f, "01-create-validation");

                    // Пароли не совпадают.
                    password.Text = MasterPassword;
                    confirm.Text = MasterPassword + "x";
                    Click(f, "btnOk");
                    Check(error.Visible && error.Text.Contains("не совпадают"), "mismatch is rejected: " + error.Text);
                    Check(f.Visible && !File.Exists(vaultPath), "nothing is created while the input is invalid");

                    // Кнопка «показать пароль».
                    show.Checked = true;
                    Check(!password.UseSystemPasswordChar && !confirm.UseSystemPasswordChar, "passwords are shown");
                    show.Checked = false;
                    Check(password.UseSystemPasswordChar && password.Text == MasterPassword, "passwords are hidden again, text is kept");

                    confirm.Text = MasterPassword;
                    Check(hint.Text.Contains("длина"), "hint for a good password: " + hint.Text);
                    Shot(f, "02-create");

                    Click(f, "btnOk");
                    WaitDecided(f, 20000, "the vault to be created");
                });

                Check(result == DialogResult.OK, "dialog result is OK");
                session = form.TakeSession();
                Check(session != null, "the dialog returns an open vault");
                Check(File.Exists(vaultPath), "the vault file exists");
                Check(session.Data.Entries.Count == 0 && session.Data.Groups.Count == 0, "a new vault is empty");
            }
        }

        private static void EmptyMainWindow()
        {
            OpenMain();

            Check(GroupNames().Length == 2 && GroupNames()[0] == "Все записи" && GroupNames()[1] == "Без группы", "only the built-in rows in the group list");
            Check(SelectedGroup() == "Все записи", "'all entries' is selected");
            Check(Entries.Items.Count == 0, "no entries");
            Label empty = Find<Label>(main, "lblEmpty");
            Check(empty.Visible && empty.Text.Contains("Добавить"), "empty state hint: " + empty.Text);
            Check(StatusText("lblCount") == "Записей: 0", "counter: " + StatusText("lblCount"));

            Check(Tool("toolbar", "btnAdd").Enabled, "'add' is enabled");
            Check(!Tool("toolbar", "btnEdit").Enabled && !Tool("toolbar", "btnDelete").Enabled, "'edit' and 'delete' need a selection");
            Check(!Tool("toolbar", "btnCopyLogin").Enabled && !Tool("toolbar", "btnCopyPassword").Enabled && !Tool("toolbar", "btnMove").Enabled, "copy and move need a selection");
            Check(!Tool("groupBar", "btnGroupEdit").Enabled && !Tool("groupBar", "btnGroupDelete").Enabled, "built-in rows cannot be renamed or deleted");
            Shot(main, "03-main-empty");
        }

        private static void CreateGroups()
        {
            AddGroup("Работа");
            Check(SelectedGroup() == "Работа", "a new group becomes selected");
            Check(StatusText("lblMessage").Contains("Работа") && StatusText("lblMessage").Contains("создана"), "status message: " + StatusText("lblMessage"));
            AddGroup("  Личное  ");
            AddGroup("Финансы");

            // Пустое название и повтор названия (без учёта регистра).
            SelectGroup("Все записи");
            Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
            {
                Label error = Find<Label>(box, "lblError");
                TextBox input = Find<TextBox>(box, "txtName");
                ComboBox parent = Find<ComboBox>(box, "cmbParent");
                Check(box.Text == "Новая группа" && input.Text == "" && !error.Visible, "empty dialog");
                Check(parent.SelectedItem.ToString() == "Верхний уровень", "the top level is offered when no group is selected");
                SameList(new[] { "Верхний уровень", "Личное", "Работа", "Финансы" }, ComboItems(parent), "places for the new group");

                Click(box, "btnOk");
                Check(box.Visible && error.Visible && error.Text.Contains("Введите"), "empty name: " + error.Text);

                input.Text = "работа";
                Check(!error.Visible, "typing clears the error");
                Click(box, "btnOk");
                Check(box.Visible && error.Visible && error.Text.Contains("уже существует"), "duplicate name: " + error.Text);
                Shot(box, "04-group-duplicate");
                Click(box, "btnCancel");
            });

            SameList(new[] { "Все записи", "Личное", "Работа", "Финансы", "Без группы" }, GroupNames(), "group list");
            Check(session.Data.Groups.Count == 3, "three groups in the vault");
        }

        private static void CreateEntries()
        {
            // Пустая форма не сохраняется.
            SelectGroup("Все записи");
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnAdd"); }, delegate(EntryForm f)
            {
                Label error = Find<Label>(f, "lblError");
                Check(Find<ComboBox>(f, "cmbGroup").SelectedItem.ToString() == "Без группы", "no group by default");
                Check(Find<TextBox>(f, "txtPassword").UseSystemPasswordChar, "password is masked");
                Click(f, "btnOk");
                Check(f.Visible && error.Visible && error.Text.Contains("Заполните"), "empty entry is rejected: " + error.Text);

                // Генератор паролей.
                Click(f, "btnGenerate");
                TextBox password = Find<TextBox>(f, "txtPassword");
                string first = password.Text;
                Check(first.Length == 20, "generated password length: " + first.Length);
                Check(Find<CheckBox>(f, "chkShow").Checked && !password.UseSystemPasswordChar, "generated password is shown");
                Click(f, "btnGenerate");
                Check(password.Text != first && password.Text.Length == 20, "every click gives a new password");
                Click(f, "btnCancel");
            });
            Check(session.Data.Entries.Count == 0, "a cancelled dialog adds nothing");

            AddEntry("Почта Gmail", "ivan.petrov@example.com", "Qw7!kPz#2026mail", "Личное");
            Check(SelectedGroup() == "Все записи", "the list stays on 'all entries'");
            Check(SelectedTitles().Length == 1 && SelectedTitles()[0] == "Почта Gmail", "the new entry is selected");
            Check(StatusText("lblMessage") == "Запись добавлена", "status message: " + StatusText("lblMessage"));

            SelectGroup("Работа");
            AddEntry("GitLab — рабочий", "i.petrov", "glpat-N8s2xQ4vT1", "Работа");
            Check(SelectedGroup() == "Работа" && Titles().Length == 1, "an entry added into the open group appears in it");

            // Запись создаётся в другой группе — список переходит туда, чтобы её было видно.
            AddEntry("Госуслуги", "70001234567", "G0su$lugi-2026", "Личное");
            Check(SelectedGroup() == "Личное", "the list follows the new entry to its group");
            Check(SelectedTitles().Length == 1 && SelectedTitles()[0] == "Госуслуги", "and selects it");

            SelectGroup("Все записи");
            AddEntry("VPN офиса", "i.petrov", "Vpn$ecret-44", "Работа");
            AddEntry("Сбербанк Онлайн", "70001234567", "Sb3r!Bank#77", "Финансы");
            AddEntry("Wi-Fi дома\r\nСеть HomeNet_5G, роутер в прихожей", "admin", "wifi-pass-8842", null);
            AddEntry("Ozon", "ivan.petrov@example.com", "0z0n-Shop!55", "Личное");
            AddEntry("Хостинг: панель управления", "ipetrov", "H0st!ng-Panel-9", "Работа");

            SelectGroup("Все записи");
            SameList(new[]
            {
                "GitLab — рабочий", "Ozon", "VPN офиса", "Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей",
                "Госуслуги", "Почта Gmail", "Сбербанк Онлайн", "Хостинг: панель управления"
            }, Titles(), "entries sorted by description");

            Check(Cell("Почта Gmail", 1) == "ivan.petrov@example.com", "login column");
            Check(Cell("Почта Gmail", 2) == Mask, "password is masked in the list: " + Cell("Почта Gmail", 2));
            Check(Cell("Почта Gmail", 3) == "Личное", "group column");
            Check(Cell("Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей", 3) == "", "no group name for an ungrouped entry");
            Check(StatusText("lblCount") == "Записей: 8", "counter: " + StatusText("lblCount"));
            Check(!Find<Label>(main, "lblEmpty").Visible, "empty hint is hidden");

            Entry wifi = session.Data.Query(GroupFilter.Ungrouped, null)[0];
            Check(wifi.Description == "Wi-Fi дома\nСеть HomeNet_5G, роутер в прихожей", "multi-line description is stored with line breaks");

            SelectEntries("Почта Gmail");
            Shot(main, "05-main");
        }

        private static void FilterByGroup()
        {
            Check(GroupCount("Все записи") == 8 && GroupCount("Работа") == 3 && GroupCount("Личное") == 3 &&
                  GroupCount("Финансы") == 1 && GroupCount("Без группы") == 1, "counters in the group list");

            SelectGroup("Работа");
            SameList(new[] { "GitLab — рабочий", "VPN офиса", "Хостинг: панель управления" }, Titles(), "entries of one group");
            Check(StatusText("lblCount") == "Показано: 3 из 8", "counter: " + StatusText("lblCount"));
            Check(Tool("groupBar", "btnGroupEdit").Enabled && Tool("groupBar", "btnGroupDelete").Enabled, "a real group can be renamed and deleted");

            SelectGroup("Без группы");
            SameList(new[] { "Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей" }, Titles(), "ungrouped entries");
            Check(!Tool("groupBar", "btnGroupEdit").Enabled, "'no group' cannot be renamed");

            // Новая запись по умолчанию попадает в открытую группу.
            SelectGroup("Работа");
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnAdd"); }, delegate(EntryForm f)
            {
                Check(Find<ComboBox>(f, "cmbGroup").SelectedItem.ToString() == "Работа", "current group is preselected");
                SameList(new[] { "Без группы", "Личное", "Работа", "Финансы" }, ComboItems(Find<ComboBox>(f, "cmbGroup")), "group choices");
                Click(f, "btnCancel");
            });

            SelectEntries("GitLab — рабочий");
            Shot(main, "06-main-group");
        }

        private static void EditEntry()
        {
            SelectGroup("Работа");
            SelectEntries("VPN офиса");
            Check(Tool("toolbar", "btnEdit").Enabled, "'edit' is enabled for one entry");

            // Отмена ничего не меняет.
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnEdit"); }, delegate(EntryForm f)
            {
                Check(f.Text == "Изменение записи", "dialog title");
                Check(Find<TextBox>(f, "txtDescription").Text == "VPN офиса", "description is loaded");
                Check(Find<TextBox>(f, "txtLogin").Text == "i.petrov", "login is loaded");
                Check(Find<TextBox>(f, "txtPassword").Text == "Vpn$ecret-44", "password is loaded");
                Check(Find<ComboBox>(f, "cmbGroup").SelectedItem.ToString() == "Работа", "group is loaded");
                Find<TextBox>(f, "txtLogin").Text = "someone-else";
                Click(f, "btnCancel");
            });
            Check(Cell("VPN офиса", 1) == "i.petrov", "cancel keeps the entry");

            // Меняем логин, пароль и группу.
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnEdit"); }, delegate(EntryForm f)
            {
                Find<TextBox>(f, "txtLogin").Text = "i.petrov@corp.example";
                Find<TextBox>(f, "txtPassword").Text = "N3w-Vpn-pass";
                SelectCombo(Find<ComboBox>(f, "cmbGroup"), "Личное");
                Find<CheckBox>(f, "chkShow").Checked = true;
                Shot(f, "07-entry-edit");
                Click(f, "btnOk");
            });

            Check(SelectedGroup() == "Личное", "the list follows the entry to its new group");
            Check(SelectedTitles().Length == 1 && SelectedTitles()[0] == "VPN офиса", "the edited entry stays selected");
            Check(Cell("VPN офиса", 1) == "i.petrov@corp.example" && Cell("VPN офиса", 3) == "Личное", "new values are shown");
            Entry entry = FindEntry("VPN офиса");
            Check(entry.Password == "N3w-Vpn-pass", "password is updated");
            Check(GroupCount("Работа") == 2 && GroupCount("Личное") == 4, "counters after the move");

            // Многострочное описание возвращается в форму с переводами строк.
            SelectGroup("Без группы");
            SelectEntries("Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей");
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnEdit"); }, delegate(EntryForm f)
            {
                Check(Find<TextBox>(f, "txtDescription").Lines.Length == 2, "two lines in the description box");
                Click(f, "btnCancel");
            });
        }

        private static void MoveByMenu()
        {
            SelectGroup("Все записи");
            SelectEntries("Ozon", "Госуслуги");
            Check(Tool("toolbar", "btnMove").Enabled && !Tool("toolbar", "btnEdit").Enabled, "several entries: move is enabled, edit is not");

            ToolStripItemCollection menu = MoveMenu();
            SameList(new[] { "Личное", "Работа", "Финансы", "-", "Без группы", "-", "Новая группа…" }, MenuTexts(menu), "'to group' menu");
            Check(!MenuItem(menu, "Личное").Enabled, "the group the entries are already in is disabled");
            Check(MenuItem(menu, "Финансы").Enabled && MenuItem(menu, "Без группы").Enabled, "other targets are enabled");

            MenuItem(menu, "Финансы").PerformClick();
            Pump(50);
            Check(Cell("Ozon", 3) == "Финансы" && Cell("Госуслуги", 3) == "Финансы", "both entries moved");
            Check(GroupCount("Финансы") == 3 && GroupCount("Личное") == 2, "counters after the move");
            Check(StatusText("lblMessage").Contains("Перемещено") && StatusText("lblMessage").Contains("Финансы") && StatusText("lblMessage").Contains("2 записи"),
                "status message: " + StatusText("lblMessage"));
            SameList(new[] { "Ozon", "Госуслуги" }, SelectedTitles(), "moved entries stay selected");

            // В «Без группы».
            SelectEntries("Ozon");
            MenuItem(MoveMenu(), "Без группы").PerformClick();
            Pump(50);
            Check(Cell("Ozon", 3) == "" && GroupCount("Без группы") == 2, "entry moved out of all groups");
            Check(!MenuItem(MoveMenu(), "Без группы").Enabled, "'no group' is now disabled for it");

            // В новую группу, которая создаётся на ходу.
            Drive<GroupForm>(delegate { MenuItem(MoveMenu(), "Новая группа…").PerformClick(); }, delegate(GroupForm box)
            {
                Check(Find<ComboBox>(box, "cmbParent").SelectedItem.ToString() == "Верхний уровень", "a new group goes to the top level by default");
                Find<TextBox>(box, "txtName").Text = "Покупки";
                Click(box, "btnOk");
            });
            Check(Cell("Ozon", 3) == "Покупки" && GroupCount("Покупки") == 1, "entry moved into the new group");
            SameList(new[] { "Все записи", "Личное", "Покупки", "Работа", "Финансы", "Без группы" }, GroupNames(), "group list with the new group");

            // Внутри группы: перемещённая запись исчезает из списка этой группы.
            SelectGroup("Финансы");
            SelectEntries("Госуслуги");
            MenuItem(MoveMenu(), "Личное").PerformClick();
            Pump(50);
            SameList(new[] { "Сбербанк Онлайн" }, Titles(), "the moved entry leaves the open group");
            Check(GroupCount("Личное") == 3, "and appears in the target group");
        }

        private static void MoveByDragDrop()
        {
            SelectGroup("Все записи");
            SelectEntries("Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей", "Сбербанк Онлайн");
            var data = new DataObject("KeyBox.EntryIds", SelectedIds());

            GroupTree tree = Tree;
            Check(tree.AllowDrop, "the group tree accepts drops");

            // «Все записи» — не группа, записи туда бросить нельзя.
            DragEventArgs over = DragArgs(data, "Все записи");
            Raise(tree, "OnDragOver", over);
            Check(over.Effect == DragDropEffects.None && tree.DropNode == null, "'all entries' is not a drop target for entries");

            // Чужие данные не принимаются.
            DragEventArgs foreign = DragArgs(new DataObject(DataFormats.Text, "text"), "Личное");
            Raise(tree, "OnDragOver", foreign);
            Check(foreign.Effect == DragDropEffects.None, "foreign data is not accepted");

            over = DragArgs(data, "Личное");
            Raise(tree, "OnDragOver", over);
            Check(over.Effect == DragDropEffects.Move && tree.DropNode == GroupNode("Личное"),
                "a group is a drop target and is highlighted: effect " + over.Effect + ", highlighted " +
                (tree.DropNode == null ? "nothing" : PathOf(tree.DropNode)) + ", row " + GroupNode("Личное").Bounds +
                ", point " + tree.PointToClient(new Point(over.X, over.Y)));
            Shot(main, "08-drag-over-group");

            Raise(tree, "OnDragDrop", over);
            Pump(50);
            Check(tree.DropNode == null, "highlight is removed after the drop");
            Check(Cell("Сбербанк Онлайн", 3) == "Личное" && Cell("Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей", 3) == "Личное", "dropped entries moved");
            Check(GroupCount("Личное") == 5 && GroupCount("Финансы") == 0, "counters after the drop");

            // Опустевшая группа объясняет, как её наполнить.
            SelectGroup("Финансы");
            Label empty = Find<Label>(main, "lblEmpty");
            Check(empty.Visible && empty.Text.Contains("В этой группе"), "empty group hint: " + empty.Text);
            Shot(main, "08a-empty-group");
            SelectGroup("Все записи");

            // Обратно: в «Без группы» и в «Финансы».
            SelectEntries("Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей");
            DragEventArgs toNone = DragArgs(new DataObject("KeyBox.EntryIds", SelectedIds()), "Без группы");
            Raise(tree, "OnDragOver", toNone);
            Check(toNone.Effect == DragDropEffects.Move, "'no group' is a drop target");
            Raise(tree, "OnDragDrop", toNone);
            Pump(50);
            Check(Cell("Wi-Fi дома Сеть HomeNet_5G, роутер в прихожей", 3) == "", "entry dropped on 'no group'");

            SelectEntries("Сбербанк Онлайн", "Госуслуги");
            DragEventArgs toFinance = DragArgs(new DataObject("KeyBox.EntryIds", SelectedIds()), "Финансы");
            Raise(tree, "OnDragOver", toFinance);
            Raise(tree, "OnDragDrop", toFinance);
            Pump(50);
            Check(GroupCount("Финансы") == 2 && GroupCount("Личное") == 2, "entries dropped back");

            // Уход курсора с дерева снимает подсветку.
            Raise(tree, "OnDragOver", DragArgs(data, "Работа"));
            Check(tree.DropNode != null, "highlight is on");
            Raise(tree, "OnDragLeave", EventArgs.Empty);
            Check(tree.DropNode == null, "highlight is off after the cursor leaves");
        }

        private static void Search()
        {
            SelectGroup("Работа");
            SetSearch("petrov");
            Check(SelectedGroup() == "Все записи", "search starts across all groups");
            SameList(new[] { "GitLab — рабочий", "Ozon", "VPN офиса", "Почта Gmail", "Хостинг: панель управления" }, Titles(), "search by login");
            Check(StatusText("lblCount") == "Показано: 5 из 8", "counter: " + StatusText("lblCount"));

            SetSearch("ПОЧТА");
            SameList(new[] { "Почта Gmail" }, Titles(), "search in the description ignores case");

            SetSearch("финансы");
            SameList(new[] { "Госуслуги", "Сбербанк Онлайн" }, Titles(), "search by group name");

            SetSearch("petrov работа");
            SameList(new[] { "GitLab — рабочий", "Хостинг: панель управления" }, Titles(), "several words must all match");

            // Выбор группы при активном поиске сужает результат до этой группы.
            SetSearch("petrov");
            SelectGroup("Личное");
            SameList(new[] { "VPN офиса", "Почта Gmail" }, Titles(), "search inside a chosen group");

            SetSearch("Sb3r");
            Check(Titles().Length == 0, "passwords are not searched");
            Label empty = Find<Label>(main, "lblEmpty");
            Check(empty.Visible && empty.Text.Contains("Ничего не найдено"), "nothing found hint: " + empty.Text);
            Shot(main, "09-search-nothing");

            SetSearch("");
            SelectGroup("Все записи");
            Check(Titles().Length == 8 && !empty.Visible, "clearing the search restores the list");
        }

        private static void ShowPasswordsAndSort()
        {
            SelectGroup("Все записи");
            ClickTool("toolbar", "btnShow");
            Check(Cell("Почта Gmail", 2) == "Qw7!kPz#2026mail", "password is shown: " + Cell("Почта Gmail", 2));
            Check(((ToolStripButton)Tool("toolbar", "btnShow")).Checked, "button stays pressed");
            SelectEntries("Сбербанк Онлайн");
            Shot(main, "10-passwords-shown");
            ClickTool("toolbar", "btnShow");
            Check(Cell("Почта Gmail", 2) == Mask, "password is hidden again");
            SameList(new[] { "Сбербанк Онлайн" }, SelectedTitles(), "selection survives the refresh");

            // Сортировка щелчком по заголовку.
            ListView list = Entries;
            Raise(list, "OnColumnClick", new ColumnClickEventArgs(1));
            string[] byLogin = Column(1);
            Check(byLogin[0] == "70001234567" && byLogin[byLogin.Length - 1] == "ivan.petrov@example.com", "ascending by login: " + string.Join(", ", byLogin));
            Raise(list, "OnColumnClick", new ColumnClickEventArgs(1));
            Check(Column(1)[0] == "ivan.petrov@example.com", "descending by login");

            string[] before = Titles();
            Raise(list, "OnColumnClick", new ColumnClickEventArgs(2));
            SameList(before, Titles(), "clicking the password column does not sort", true);

            Raise(list, "OnColumnClick", new ColumnClickEventArgs(3));
            Check(Column(3)[0] == "" && Column(3)[Column(3).Length - 1] == "Финансы", "ascending by group: " + string.Join(", ", Column(3)));

            Raise(list, "OnColumnClick", new ColumnClickEventArgs(0));
            Check(Titles()[0] == "GitLab — рабочий", "back to sorting by description");
        }

        private static void Shortcuts()
        {
            SelectGroup("Все записи");

            Key(Keys.Control | Keys.H);
            Check(Cell("Ozon", 2) == "0z0n-Shop!55", "Ctrl+H shows passwords");
            Key(Keys.Control | Keys.H);
            Check(Cell("Ozon", 2) == Mask, "Ctrl+H hides them again");

            SetSearch("ozon");
            Check(Titles().Length == 1, "search is active");
            Key(Keys.Escape);
            Check(SearchBox.Text == "" && Titles().Length == 8, "Esc clears the search");

            // Ins открывает новую запись, Ctrl+G — новую группу.
            Drive<EntryForm>(delegate { Key(Keys.Insert); }, delegate(EntryForm f) { Click(f, "btnCancel"); });
            Drive<GroupForm>(delegate { Key(Keys.Control | Keys.G); }, delegate(GroupForm box) { Click(box, "btnCancel"); });

            // В списке: Ctrl+A, F2, Del.
            Raise(Entries, "OnKeyDown", new KeyEventArgs(Keys.Control | Keys.A));
            Check(Entries.SelectedItems.Count == 8, "Ctrl+A selects everything");

            SelectEntries("Ozon");
            Drive<EntryForm>(delegate { Raise(Entries, "OnKeyDown", new KeyEventArgs(Keys.F2)); }, delegate(EntryForm f)
            {
                Check(Find<TextBox>(f, "txtDescription").Text == "Ozon", "F2 opens the selected entry");
                Click(f, "btnCancel");
            });
            Drive<MsgBox>(delegate { Raise(Entries, "OnKeyDown", new KeyEventArgs(Keys.Delete)); }, delegate(MsgBox box)
            {
                Check(Find<Label>(box, "lblText").Text.Contains("Ozon"), "Del asks about the selected entry");
                Click(box, "btnCancel");
            });
            Check(Titles().Length == 8, "nothing is deleted after 'cancel'");

            // Двойной щелчок / Enter по записи.
            Drive<EntryForm>(delegate { Raise(Entries, "OnItemActivate", EventArgs.Empty); }, delegate(EntryForm f) { Click(f, "btnCancel"); });

            // В списке групп: F2 и Del.
            SelectGroup("Покупки");
            Drive<GroupForm>(delegate { Raise(Tree, "OnKeyDown", new KeyEventArgs(Keys.F2)); }, delegate(GroupForm box)
            {
                Check(box.Text == "Изменение группы" && Find<TextBox>(box, "txtName").Text == "Покупки", "F2 opens the selected group");
                Click(box, "btnCancel");
            });
            Drive<MsgBox>(delegate { Raise(Tree, "OnKeyDown", new KeyEventArgs(Keys.Delete)); }, delegate(MsgBox box) { Click(box, "btnCancel"); });
            Check(HasGroup("Покупки"), "the group is still there after 'cancel'");
        }

        private static void DeleteEntry()
        {
            SelectGroup("Все записи");
            SelectEntries("Хостинг: панель управления");

            Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box)
            {
                string text = Find<Label>(box, "lblText").Text;
                Check(text.Contains("Хостинг: панель управления") && text.Contains("нельзя"), "question names the entry: " + text);
                Check(box.ActiveControl == Find<Button>(box, "btnCancel"), "'cancel' is the default for a destructive action");
                Shot(box, "11-confirm-delete");
                Click(box, "btnCancel");
            });
            Check(Titles().Length == 8, "cancel keeps the entry");

            Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box) { Click(box, "btnOk"); });
            Check(Titles().Length == 7 && FindEntry("Хостинг: панель управления") == null, "entry is deleted");
            Check(StatusText("lblMessage").Contains("Удалено: 1 запись"), "status message: " + StatusText("lblMessage"));
            Check(GroupCount("Работа") == 1, "group counter after deletion");
            Check(!Tool("toolbar", "btnDelete").Enabled, "nothing is selected after deletion");

            // Несколько записей сразу.
            AddEntry("Временная 1", "tmp1", "p1", null);
            AddEntry("Временная 2", "tmp2", "p2", null);
            SelectGroup("Все записи");
            SelectEntries("Временная 1", "Временная 2");
            Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box)
            {
                Check(Find<Label>(box, "lblText").Text.Contains("2 выбранные записи"), "question for several entries: " + Find<Label>(box, "lblText").Text);
                Click(box, "btnOk");
            });
            Check(Titles().Length == 7, "both entries are deleted");
        }

        private static void RenameAndDeleteGroup()
        {
            SelectGroup("Работа");
            Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupEdit"); }, delegate(GroupForm box)
            {
                TextBox input = Find<TextBox>(box, "txtName");
                Label error = Find<Label>(box, "lblError");
                Check(input.Text == "Работа", "current name is offered");
                Check(Find<ComboBox>(box, "cmbParent").SelectedItem.ToString() == "Верхний уровень", "current place is offered");

                input.Text = "личное";
                Click(box, "btnOk");
                Check(box.Visible && error.Visible && error.Text.Contains("уже существует"), "name of another group is rejected");

                input.Text = "Работа и проекты";
                Click(box, "btnOk");
            });
            SameList(new[] { "Все записи", "Личное", "Покупки", "Работа и проекты", "Финансы", "Без группы" }, GroupNames(), "renamed group");
            Check(SelectedGroup() == "Работа и проекты", "renamed group stays selected");
            Check(Cell("GitLab — рабочий", 3) == "Работа и проекты", "entries show the new name");

            // Удаление группы с записями: записи остаются.
            SelectGroup("Финансы");
            int before = session.Data.Entries.Count;
            Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box)
            {
                string text = Find<Label>(box, "lblText").Text;
                Check(text.Contains("Финансы") && text.Contains("2 записи") && text.Contains("Без группы"), "question explains what happens to entries: " + text);
                Shot(box, "12-confirm-delete-group");
                Click(box, "btnOk");
            });
            Check(!HasGroup("Финансы"), "group is deleted");
            Check(session.Data.Entries.Count == before, "entries are kept");
            Check(SelectedGroup() == "Без группы", "the list shows where the entries went");
            Check(Titles().Length == 3 && Cell("Сбербанк Онлайн", 3) == "", "released entries are ungrouped");

            // Пустая группа удаляется без пояснений про записи.
            SelectGroup("Все записи");
            SelectEntries("Ozon");
            MenuItem(MoveMenu(), "Личное").PerformClick();
            Pump(50);
            SelectGroup("Покупки");
            Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box)
            {
                Check(!Find<Label>(box, "lblText").Text.Contains("Без группы"), "no remark about entries for an empty group");
                Click(box, "btnOk");
            });
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "Без группы" }, GroupNames(), "groups after deletion");
            Check(SelectedGroup() == "Все записи", "selection returns to all entries");
        }

        private static void LongTexts()
        {
            string longName = ("Очень длинное название группы, которое не помещается в отведённое место " + new string('я', 100))
                .Substring(0, VaultData.MaxGroupNameLength);
            AddGroup(longName);
            string longDescription = "Очень длинное описание записи: " + new string('ж', 300) + " конец";
            AddEntry(longDescription, new string('l', 120) + "@example.com", new string('p', 200), longName);

            SelectGroup("Все записи");
            ClickTool("toolbar", "btnShow");
            Shot(main, "13-long-texts");
            ClickTool("toolbar", "btnShow");

            // Вопрос с длинным названием не должен раздувать окно.
            SelectEntries(Ui.SingleLine(longDescription));
            Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box)
            {
                Check(box.Width <= Ui.S(560), "message box keeps a sane width: " + box.Width);
                Shot(box, "14-long-question");
                Click(box, "btnOk");
            });
            SelectGroup(longName);
            Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box) { Click(box, "btnOk"); });
            Check(session.Data.Groups.Count == 2 && session.Data.Entries.Count == 7, "temporary data is removed");
        }

        // Эти пять проверок выполняются только в режиме --clipboard-child (см. ClipboardChild).

        private static void ClipboardCopy()
        {
            Check(!Clipboard.ContainsText(), "the isolated clipboard starts empty");
            SelectEntries("Почта Gmail");

            ClickTool("toolbar", "btnCopyPassword");
            Check(Clipboard.GetText() == "Qw7!kPz#2026mail", "password is in the clipboard");
            Check(ClipboardGuard.Pending && ClipboardGuard.SecondsLeft == MainForm.ClipboardClearSeconds, "countdown has started");
            Check(StatusText("lblMessage").Contains("Пароль скопирован") && StatusText("lblMessage").Contains("через 30 с"),
                "status: " + StatusText("lblMessage"));

            ClickTool("toolbar", "btnCopyLogin");
            Check(Clipboard.GetText() == "ivan.petrov@example.com", "login is in the clipboard");
            Check(StatusText("lblMessage").Contains("Логин скопирован"), "status: " + StatusText("lblMessage"));

            Raise(Entries, "OnKeyDown", new KeyEventArgs(Keys.Control | Keys.C));
            Check(Clipboard.GetText() == "Qw7!kPz#2026mail", "Ctrl+C copies the password");
            Raise(Entries, "OnKeyDown", new KeyEventArgs(Keys.Control | Keys.B));
            Check(Clipboard.GetText() == "ivan.petrov@example.com", "Ctrl+B copies the login");

            // Отсчёт идёт и виден в строке состояния.
            WaitUntil(delegate { return ClipboardGuard.SecondsLeft < MainForm.ClipboardClearSeconds; }, 4000, "the countdown to tick");
            Check(StatusText("lblMessage").Contains("через " + ClipboardGuard.SecondsLeft + " с"), "countdown in the status bar: " + StatusText("lblMessage"));
        }

        private static void ClipboardExclusion()
        {
            SelectEntries("Почта Gmail");
            ClickTool("toolbar", "btnCopyPassword");

            IDataObject copied = Clipboard.GetDataObject();
            Check(copied.GetDataPresent(DataFormats.UnicodeText), "plain text is offered");
            Check(copied.GetDataPresent("ExcludeClipboardContentFromMonitorProcessing"), "marked to stay out of clipboard monitors");
            Check(copied.GetDataPresent("CanIncludeInClipboardHistory"), "history flag is present");
            Check(copied.GetDataPresent("CanUploadToCloudClipboard"), "cloud flag is present");
            Check(ReadInt32(copied, "CanIncludeInClipboardHistory") == 0, "history flag is zero: " + ReadInt32(copied, "CanIncludeInClipboardHistory"));
            Check(ReadInt32(copied, "CanUploadToCloudClipboard") == 0, "cloud flag is zero: " + ReadInt32(copied, "CanUploadToCloudClipboard"));
        }

        private static void ClipboardClearing()
        {
            SelectEntries("Почта Gmail");
            ClickTool("toolbar", "btnCopyPassword");
            Check(Clipboard.ContainsText(), "password is in the clipboard");

            // По требованию — так программа делает при выходе.
            ClipboardGuard.ClearIfOwned();
            Check(!Clipboard.ContainsText() && !ClipboardGuard.Pending, "clipboard is cleared on demand");
            Check(StatusText("lblMessage").Contains("очищен"), "status: " + StatusText("lblMessage"));
            ClipboardGuard.ClearIfOwned();   // повторный вызов безвреден

            // По таймеру.
            Check(ClipboardGuard.Copy("timed secret", "Пароль", 2), "copy with a short timeout");
            Check(Clipboard.GetText() == "timed secret", "the value is in the clipboard");
            WaitUntil(delegate { return !ClipboardGuard.Pending; }, 6000, "the clipboard timer");
            Check(!Clipboard.ContainsText(), "clipboard is cleared by the timer");
            Check(StatusText("lblMessage").Contains("очищен"), "status after the timer: " + StatusText("lblMessage"));
        }

        private static void ClipboardForeignContent()
        {
            Check(ClipboardGuard.Copy("our secret", "Пароль", 2), "copy");
            Clipboard.SetText("copied by the user from another program");
            WaitUntil(delegate { return !ClipboardGuard.Pending; }, 6000, "the clipboard timer");
            Check(Clipboard.GetText() == "copied by the user from another program", "content copied later by someone else is left alone");

            // То же при очистке по требованию.
            Check(ClipboardGuard.Copy("our secret", "Пароль", 30), "copy again");
            Clipboard.SetText("still not ours");
            ClipboardGuard.ClearIfOwned();
            Check(Clipboard.GetText() == "still not ours", "clearing on demand also leaves foreign content alone");
            Clipboard.Clear();
        }

        private static void ClipboardEmptyPassword()
        {
            SelectEntries("Без пароля");
            Check(Cell("Без пароля", 2) == "", "an empty password is shown as empty, not as a mask");

            ClickTool("toolbar", "btnCopyPassword");
            Check(!Clipboard.ContainsText() && !ClipboardGuard.Pending, "nothing is copied");
            Check(StatusText("lblMessage").Contains("не задан"), "status: " + StatusText("lblMessage"));

            ClickTool("toolbar", "btnCopyLogin");
            Check(Clipboard.GetText() == "nopass", "the login of the same entry is copied");
            ClipboardGuard.ClearIfOwned();
        }

        /// <summary>
        /// Вложенные группы. К началу сценария в хранилище две группы («Личное», «Работа и проекты»)
        /// и семь записей; в конце всё добавленное убирается, и остаётся то же самое.
        /// </summary>
        private static void NestedGroups()
        {
            // --- Подгруппа создаётся внутри выбранной группы.
            SelectGroup("Работа и проекты");
            Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
            {
                ComboBox parent = Find<ComboBox>(box, "cmbParent");
                Check(parent.SelectedItem.ToString() == "Работа и проекты", "the selected group is offered as the place for a new one");
                SameList(new[] { "Верхний уровень", "Личное", "Работа и проекты" }, ComboItems(parent), "places for the new group");
                Find<TextBox>(box, "txtName").Text = "Серверы";
                Shot(box, "23-new-subgroup");
                Click(box, "btnOk");
            });
            Check(SelectedGroup() == "Работа и проекты / Серверы", "the new subgroup is selected: " + SelectedGroup());
            Check(StatusText("lblMessage").Contains("Работа и проекты / Серверы"), "status names the full path: " + StatusText("lblMessage"));
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "> Серверы", "Без группы" }, GroupNames(), "tree with a subgroup");

            // Третий уровень.
            AddGroup("Тестовые", "Работа и проекты / Серверы");
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "> Серверы", ">> Тестовые", "Без группы" }, GroupNames(), "tree with three levels");
            Check(session.Data.Groups.Count == 4, "groups in the vault");

            // Среди соседних групп название не повторяется.
            SelectGroup("Работа и проекты");
            Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
            {
                Label error = Find<Label>(box, "lblError");
                Find<TextBox>(box, "txtName").Text = "серверы";
                Click(box, "btnOk");
                Check(box.Visible && error.Visible && error.Text.Contains("уже есть подгруппа"), "a sibling with the same name is rejected: " + error.Text);
                SelectCombo(Find<ComboBox>(box, "cmbParent"), "Личное");
                Check(!error.Visible, "choosing another place clears the error");
                Click(box, "btnCancel");
            });
            Check(session.Data.Groups.Count == 4, "a cancelled dialog adds nothing");

            // --- Записи во вложенных группах.
            SelectGroup("Все записи");
            AddEntry("Сервер сборки", "build", "B1ld-pass", "Работа и проекты / Серверы");
            AddEntry("Тестовый стенд", "qa", "Qa-pass", "Работа и проекты / Серверы / Тестовые");
            Check(SelectedGroup() == "Все записи" && Titles().Length == 9, "new entries are visible in 'all entries'");
            Check(Cell("Сервер сборки", 3) == "Работа и проекты / Серверы", "the group column shows the full path: " + Cell("Сервер сборки", 3));
            Check(Cell("Тестовый стенд", 3) == "Работа и проекты / Серверы / Тестовые", "path of the third level");
            Check(GroupCount("Работа и проекты") == 1 && GroupCount("Работа и проекты / Серверы") == 1 &&
                  GroupCount("Работа и проекты / Серверы / Тестовые") == 1 && GroupCount("Все записи") == 9,
                "each group counts its own entries only");

            // Группа показывает только свои записи; подгруппы — отдельно.
            SelectGroup("Работа и проекты");
            SameList(new[] { "GitLab — рабочий" }, Titles(), "a parent group lists its own entries");
            SelectGroup("Работа и проекты / Серверы");
            SameList(new[] { "Сервер сборки" }, Titles(), "a subgroup lists its entries");

            // Новая запись по умолчанию попадает в открытую подгруппу.
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnAdd"); }, delegate(EntryForm f)
            {
                ComboBox groups = Find<ComboBox>(f, "cmbGroup");
                Check(groups.SelectedItem.ToString() == "Работа и проекты / Серверы", "the open subgroup is preselected: " + groups.SelectedItem);
                SameList(new[] { "Без группы", "Личное", "Работа и проекты", "Работа и проекты / Серверы", "Работа и проекты / Серверы / Тестовые" },
                    ComboItems(groups), "group choices are full paths in tree order");
                Click(f, "btnCancel");
            });

            // Меню «В группу» — те же пути.
            SelectGroup("Работа и проекты");
            SelectEntries("GitLab — рабочий");
            SameList(new[] { "Личное", "Работа и проекты", "Работа и проекты / Серверы", "Работа и проекты / Серверы / Тестовые", "-", "Без группы", "-", "Новая группа…" },
                MenuTexts(MoveMenu()), "'to group' menu with nested groups");
            MenuItem(MoveMenu(), "Работа и проекты / Серверы").PerformClick();
            Pump(50);
            Label empty = Find<Label>(main, "lblEmpty");
            Check(Titles().Length == 0 && empty.Visible && empty.Text.Contains("подгруппах"),
                "a group whose entries are all in subgroups says so: " + empty.Text);
            Shot(main, "24-entries-in-subgroups");

            // Поиск по названию группы находит и записи её подгрупп.
            SetSearch("проекты");
            SameList(new[] { "GitLab — рабочий", "Сервер сборки", "Тестовый стенд" }, Titles(), "search by the parent group name");
            SetSearch("");

            SelectGroup("Все записи");
            SelectEntries("Сервер сборки");
            Shot(main, "25-nested-groups");

            // --- Ветка сворачивается и остаётся свёрнутой при обновлении списка.
            ClickArrow("Работа и проекты");
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "Без группы" }, GroupNames(), "a collapsed branch hides its subgroups");
            InvokeMain("RefreshAll");
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "Без группы" }, GroupNames(), "the branch stays collapsed after a refresh");
            SameList(new[] { "Сервер сборки" }, SelectedTitles(), "the selected entry survives the refresh");

            // Щелчок по стрелке раскрывает ветку и не меняет выбранную группу.
            ClickArrow("Работа и проекты");
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "> Серверы", ">> Тестовые", "Без группы" }, GroupNames(), "the arrow expands the branch");
            Check(SelectedGroup() == "Все записи", "a click on the arrow keeps the selection");
            ClickArrow("Работа и проекты");
            Check(GroupNames().Length == 4, "the arrow collapses the branch again");
            ClickArrow("Работа и проекты");

            // Выбор группы из свёрнутой ветки раскрывает её.
            ClickArrow("Работа и проекты");
            SelectGroup("Работа и проекты / Серверы / Тестовые");
            Check(GroupNames().Length == 6 && SelectedGroup() == "Работа и проекты / Серверы / Тестовые", "selecting a hidden subgroup expands its branch");

            // --- Изменение группы: название и место в дереве одним окном.
            SelectGroup("Работа и проекты / Серверы");
            Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupEdit"); }, delegate(GroupForm box)
            {
                ComboBox parent = Find<ComboBox>(box, "cmbParent");
                Check(box.Text == "Изменение группы" && Find<TextBox>(box, "txtName").Text == "Серверы", "the name is loaded");
                Check(parent.SelectedItem.ToString() == "Работа и проекты", "the place is loaded");
                // Саму группу и её подгруппы выбрать местом нельзя — их нет в списке.
                SameList(new[] { "Верхний уровень", "Личное", "Работа и проекты" }, ComboItems(parent), "allowed places");
                Find<TextBox>(box, "txtName").Text = "Серверы и стенды";
                SelectCombo(parent, "Личное");
                Shot(box, "26-edit-group");
                Click(box, "btnOk");
            });
            Check(SelectedGroup() == "Личное / Серверы и стенды", "the moved group stays selected: " + SelectedGroup());
            Check(StatusText("lblMessage").Contains("перенесена"), "status: " + StatusText("lblMessage"));
            SameList(new[] { "Все записи", "Личное", "> Серверы и стенды", ">> Тестовые", "Работа и проекты", "Без группы" }, GroupNames(), "the branch moved as a whole");
            SelectGroup("Все записи");
            Check(Cell("Сервер сборки", 3) == "Личное / Серверы и стенды" && Cell("Тестовый стенд", 3) == "Личное / Серверы и стенды / Тестовые",
                "entries follow their groups");

            // --- Перетаскивание групп.
            GroupTree tree = Tree;
            var dragged = new DataObject("KeyBox.GroupId", GroupId("Личное / Серверы и стенды"));

            DragEventArgs toWork = DragArgs(dragged, "Работа и проекты");
            Raise(tree, "OnDragOver", toWork);
            Check(toWork.Effect == DragDropEffects.Move && tree.DropNode == GroupNode("Работа и проекты"), "another group accepts a group");
            Shot(main, "27-drag-group");

            // Нельзя: туда, где группа уже лежит, в саму себя, в свою подгруппу и в «Без группы».
            foreach (string forbidden in new[] { "Личное", "Личное / Серверы и стенды", "Личное / Серверы и стенды / Тестовые", "Без группы" })
            {
                DragEventArgs refused = DragArgs(dragged, forbidden);
                Raise(tree, "OnDragOver", refused);
                Check(refused.Effect == DragDropEffects.None && tree.DropNode == null, "a group cannot be dropped on: " + forbidden);
            }

            // «Все записи» и свободное место под деревом означают верхний уровень.
            DragEventArgs toTop = DragArgs(dragged, "Все записи");
            Raise(tree, "OnDragOver", toTop);
            Check(toTop.Effect == DragDropEffects.Move && tree.DropNode == GroupNode("Все записи"), "'all entries' means the top level");
            DragEventArgs below = DragArgsBelowTree(dragged);
            Raise(tree, "OnDragOver", below);
            Check(below.Effect == DragDropEffects.Move && tree.DropNode == GroupNode("Все записи"), "free space under the tree means the top level too");
            DragEventArgs alreadyTop = DragArgs(new DataObject("KeyBox.GroupId", GroupId("Личное")), "Все записи");
            Raise(tree, "OnDragOver", alreadyTop);
            Check(alreadyTop.Effect == DragDropEffects.None, "a top-level group cannot go higher");

            Raise(tree, "OnDragDrop", toWork);
            Pump(50);
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "> Серверы и стенды", ">> Тестовые", "Без группы" }, GroupNames(), "the group is dropped into another group");
            Check(tree.DropNode == null && StatusText("lblMessage").Contains("Работа и проекты / Серверы и стенды"), "status after the drop: " + StatusText("lblMessage"));

            DragEventArgs up = DragArgs(new DataObject("KeyBox.GroupId", GroupId("Работа и проекты / Серверы и стенды / Тестовые")), "Все записи");
            Raise(tree, "OnDragOver", up);
            Raise(tree, "OnDragDrop", up);
            Pump(50);
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "> Серверы и стенды", "Тестовые", "Без группы" }, GroupNames(), "a subgroup is dropped onto the top level");

            // Одинаковые названия на одном уровне: перенос отклоняется с объяснением.
            AddGroup("Тестовые", "Личное");
            DragEventArgs clash = DragArgs(new DataObject("KeyBox.GroupId", GroupId("Личное / Тестовые")), "Все записи");
            Raise(tree, "OnDragOver", clash);
            Check(clash.Effect == DragDropEffects.Move, "the place itself is allowed");
            Drive<MsgBox>(delegate { Raise(Tree, "OnDragDrop", clash); }, delegate(MsgBox box)
            {
                Check(Find<Label>(box, "lblText").Text.Contains("уже существует"), "the clash is explained: " + Find<Label>(box, "lblText").Text);
                Click(box, "btnOk");
            });
            Check(HasGroup("Личное / Тестовые"), "the group stays where it was");

            // --- Удаление. Пустая подгруппа: простой вопрос, выбранной становится родительская группа.
            SelectGroup("Личное / Тестовые");
            Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box)
            {
                string text = Find<Label>(box, "lblText").Text;
                Check(text.Contains("«Тестовые»") && !text.Contains("подгрупп") && !text.Contains("Записи"), "plain question for an empty group: " + text);
                Click(box, "btnOk");
            });
            Check(SelectedGroup() == "Личное" && !HasGroup("Личное / Тестовые"), "after deleting a subgroup its parent is selected");

            // Группа с подгруппой и записями из середины дерева: записи поднимаются в родительскую группу.
            DragEventArgs back = DragArgs(new DataObject("KeyBox.GroupId", GroupId("Тестовые")), "Работа и проекты / Серверы и стенды");
            Raise(tree, "OnDragOver", back);
            Raise(tree, "OnDragDrop", back);
            Pump(50);
            SelectGroup("Работа и проекты / Серверы и стенды");
            Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box)
            {
                string text = Find<Label>(box, "lblText").Text;
                Check(text.Contains("вместе с её подгруппой") && text.Contains("3 записи") && text.Contains("в группе «Работа и проекты»"),
                    "the question explains what happens: " + text);
                Shot(box, "28-delete-branch");
                Click(box, "btnOk");
            });
            Check(SelectedGroup() == "Работа и проекты", "the parent group is selected after the deletion");
            SameList(new[] { "Все записи", "Личное", "Работа и проекты", "Без группы" }, GroupNames(), "the branch is gone");
            SameList(new[] { "GitLab — рабочий", "Сервер сборки", "Тестовый стенд" }, Titles(), "entries of the branch moved up to the parent");
            Check(session.Data.Entries.Count == 9, "no entry is lost");

            // Убираем добавленное: остаются прежние две группы и семь записей.
            SelectEntries("Сервер сборки", "Тестовый стенд");
            Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box) { Click(box, "btnOk"); });
            SelectGroup("Все записи");
            Check(session.Data.Groups.Count == 2 && session.Data.Entries.Count == 7 && Cell("GitLab — рабочий", 3) == "Работа и проекты",
                "the vault is back to its previous shape");
        }

        private static void About()
        {
            Drive<MsgBox>(delegate { ClickTool("toolbar", "miAbout"); }, delegate(MsgBox box)
            {
                string text = Find<Label>(box, "lblText").Text;
                Check(text.Contains("AES-256-GCM") && text.Contains("PBKDF2-HMAC-SHA512") && text.Contains("600"), "encryption is described: " + text);
                Check(text.Contains("2 группы") && text.Contains("7 записей"), "vault contents are counted: " + text);
                Check(text.Contains(Path.GetFileName(vaultPath)), "the vault file is named");
                Check(box.Width <= Ui.S(560), "the box keeps a sane width: " + box.Width);
                Shot(box, "22-about");
                Click(box, "btnOk");
            });
        }

        private static void SaveFailure()
        {
            // Мешаем записи: на месте временного файла стоит папка.
            string obstacle = vaultPath + ".tmp";
            Directory.CreateDirectory(obstacle);
            int onDisk = CountOnDisk();

            try
            {
                // Первая попытка проваливается, пользователь нажимает «Отмена».
                Drive<MsgBox>(delegate
                {
                    Drive<EntryForm>(delegate { ClickTool("toolbar", "btnAdd"); }, delegate(EntryForm f)
                    {
                        Find<TextBox>(f, "txtDescription").Text = "Запись при сбое";
                        Find<TextBox>(f, "txtLogin").Text = "unsaved";
                        Click(f, "btnOk");
                    });
                }, delegate(MsgBox box)
                {
                    string text = Find<Label>(box, "lblText").Text;
                    Check(box.Text == "Не удалось сохранить" && text.Contains("только в памяти"), "failure is explained: " + text);
                    Check(Find<Button>(box, "btnOk").Text == "Повторить", "retry is offered");
                    Shot(box, "16-save-failed");
                    Click(box, "btnCancel");
                });

                Check(FindEntry("Запись при сбое") != null, "the change is kept in memory");
                Check(CountOnDisk() == onDisk, "the file on disk is untouched");
                Check(StatusText("lblMessage").Contains("не записаны"), "a warning stays in the status bar: " + StatusText("lblMessage"));
                Shot(main, "17-unsaved-warning");

                // Следующее изменение: сбой повторяется, препятствие устраняют и жмут «Повторить».
                Drive<MsgBox>(delegate
                {
                    Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
                    {
                        Find<TextBox>(box, "txtName").Text = "Группа при сбое";
                        SelectCombo(Find<ComboBox>(box, "cmbParent"), "Верхний уровень");
                        Click(box, "btnOk");
                    });
                }, delegate(MsgBox box)
                {
                    Directory.Delete(obstacle, true);
                    Click(box, "btnOk");
                });

                Check(!StatusText("lblMessage").Contains("не записаны"), "the warning is gone after a successful save: " + StatusText("lblMessage"));
                Check(CountOnDisk() == onDisk + 2, "everything pending (the entry and the group) is written by the retry");
            }
            finally
            {
                if (Directory.Exists(obstacle)) Directory.Delete(obstacle, true);
            }

            // Убираем за собой.
            SelectGroup("Все записи");
            SelectEntries("Запись при сбое");
            Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box) { Click(box, "btnOk"); });
            SelectGroup("Группа при сбое");
            Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box) { Click(box, "btnOk"); });
        }

        private static void Persistence()
        {
            using (VaultSession copy = VaultSession.Open(vaultPath, MasterPassword))
            {
                Check(copy.Data.Groups.Count == session.Data.Groups.Count && copy.Data.Groups.Count == 2, "groups on disk: " + copy.Data.Groups.Count);
                Check(copy.Data.Entries.Count == session.Data.Entries.Count && copy.Data.Entries.Count == 7, "entries on disk: " + copy.Data.Entries.Count);
                foreach (Entry entry in session.Data.Entries)
                {
                    Entry stored = copy.Data.FindEntry(entry.Id);
                    Check(stored != null && stored.Login == entry.Login && stored.Password == entry.Password &&
                          stored.Description == entry.Description && stored.GroupId == entry.GroupId, "entry on disk: " + entry.Description);
                }
            }
            Check(File.Exists(vaultPath + ".bak"), "previous version is kept as a backup");
            Check(!File.Exists(vaultPath + ".tmp"), "no temporary file is left");

            byte[] raw = File.ReadAllBytes(vaultPath);
            Check(Encoding.ASCII.GetString(raw, 0, 6) == "KEYBOX", "file signature");
            foreach (string secret in new[] { "Qw7!kPz#2026mail", "ivan.petrov", "Gmail", MasterPassword })
            {
                Check(IndexOf(raw, Encoding.UTF8.GetBytes(secret)) < 0, "no plaintext in the file: " + secret);
            }
        }

        private static void Lock()
        {
            SelectGroup("Все записи");
            SelectEntries("Госуслуги");
            Shot(main, "18-main-final");

            MainForm window = main;
            ClickTool("toolbar", "btnLock");
            WaitUntil(delegate { return window.IsDisposed; }, 5000, "the window to close");
            Check(window.LockRequested, "the window reports that a lock was requested");

            // Так же поступает программа: после блокировки ключ и данные выбрасываются.
            session.Dispose();
            Check(session.Data == null, "decrypted data is dropped");
            session = null;
            main = null;
        }

        private static void Unlock()
        {
            using (var form = new UnlockForm(vaultPath))
            {
                Check(!form.CreateMode, "unlock mode when the file exists");
                DialogResult result = DialogResult.None;

                Drive<UnlockForm>(delegate { result = form.ShowDialog(); }, delegate(UnlockForm f)
                {
                    TextBox password = Find<TextBox>(f, "txtPassword");
                    Label error = Find<Label>(f, "lblError");
                    Check(f.Controls.Find("txtConfirm", true).Length == 0, "no confirmation field when unlocking");
                    Check(Find<Button>(f, "btnOk").Text == "Открыть", "button caption");
                    Check(Find<Label>(f, "lblPath").Text.Contains(Path.GetFileName(vaultPath)), "the file is named");
                    Shot(f, "19-unlock");

                    Click(f, "btnOk");
                    Check(error.Visible && error.Text.Contains("Введите"), "empty password: " + error.Text);

                    password.Text = MasterPassword + "!";
                    Click(f, "btnOk");
                    Check(f.IsBusy && !password.Enabled, "the dialog is busy while the password is checked");
                    WaitUntil(delegate { return !f.IsBusy; }, 20000, "the password check");
                    Check(f.Visible && error.Visible && error.Text.Contains("Неверный мастер-пароль"), "wrong password is rejected: " + error.Text);
                    Check(password.Enabled && Find<Button>(f, "btnOk").Text == "Открыть", "the dialog is usable again");
                    Shot(f, "20-unlock-wrong");

                    password.Text = MasterPassword;
                    Check(!error.Visible, "typing clears the error");
                    Click(f, "btnOk");
                    WaitDecided(f, 20000, "the vault to open");
                });

                Check(result == DialogResult.OK, "dialog result is OK");
                session = form.TakeSession();
                Check(session != null && session.Data.Entries.Count == 7 && session.Data.Groups.Count == 2, "the vault is opened with all its data");
            }

            // «Выход» в окне входа ничего не открывает.
            using (var form = new UnlockForm(vaultPath))
            {
                DialogResult result = DialogResult.None;
                Drive<UnlockForm>(delegate { result = form.ShowDialog(); }, delegate(UnlockForm f) { Click(f, "btnCancel"); });
                Check(result == DialogResult.Cancel && form.TakeSession() == null, "'exit' opens nothing");
            }
        }

        private static void ChangeMasterPassword()
        {
            OpenMain();
            Check(Titles().Length == 7, "data is shown after unlocking");

            Drive<ChangePasswordForm>(delegate { main.ChangeMasterPassword(); }, delegate(ChangePasswordForm f)
            {
                TextBox current = Find<TextBox>(f, "txtCurrent");
                TextBox replacement = Find<TextBox>(f, "txtNew");
                TextBox confirm = Find<TextBox>(f, "txtConfirm");
                Label error = Find<Label>(f, "lblError");

                Click(f, "btnOk");
                Check(error.Visible && error.Text.Contains("текущий"), "current password is required: " + error.Text);

                current.Text = MasterPassword;
                replacement.Text = "кор";
                confirm.Text = "кор";
                Click(f, "btnOk");
                Check(error.Visible && error.Text.Contains("не короче"), "short new password is rejected: " + error.Text);

                replacement.Text = NewMasterPassword;
                confirm.Text = NewMasterPassword + "?";
                Click(f, "btnOk");
                Check(error.Visible && error.Text.Contains("не совпадают"), "mismatch is rejected: " + error.Text);

                replacement.Text = MasterPassword;
                confirm.Text = MasterPassword;
                Click(f, "btnOk");
                Check(error.Visible && error.Text.Contains("совпадает с текущим"), "same password is rejected: " + error.Text);

                // Неверный текущий пароль.
                current.Text = "не тот пароль";
                replacement.Text = NewMasterPassword;
                confirm.Text = NewMasterPassword;
                Click(f, "btnOk");
                WaitUntil(delegate { return !f.IsBusy; }, 20000, "the password check");
                Check(f.Visible && error.Visible && error.Text.Contains("неверно"), "wrong current password is rejected: " + error.Text);
                Shot(f, "21-change-password");

                current.Text = MasterPassword;
                Click(f, "btnOk");
                WaitDecided(f, 30000, "the vault to be re-encrypted");
            });
            Check(StatusText("lblMessage").Contains("Мастер-пароль изменён"), "status: " + StatusText("lblMessage"));

            bool oldWorks = true;
            try
            {
                VaultSession.Open(vaultPath, MasterPassword).Dispose();
            }
            catch (VaultException ex)
            {
                oldWorks = ex.Error != VaultError.WrongPassword;
            }
            Check(!oldWorks, "the old master password no longer opens the vault");
            using (VaultSession copy = VaultSession.Open(vaultPath, NewMasterPassword))
            {
                Check(copy.Data.Entries.Count == 7, "the new master password opens it with all data");
            }

            // Хранилище продолжает работать на новом ключе.
            AddEntry("После смены пароля", "after", "x", null);
            using (VaultSession copy = VaultSession.Open(vaultPath, NewMasterPassword))
            {
                Check(copy.Data.Entries.Count == 8, "changes after the password change are saved");
            }
        }

        private static void AutoLock()
        {
            MainForm window = main;
            int entries = session.Data.Entries.Count;

            Drive<EntryForm>(delegate { window.AddEntry(); }, delegate(EntryForm f)
            {
                Find<TextBox>(f, "txtDescription").Text = "Не должна сохраниться";
                Find<TextBox>(f, "txtLogin").Text = "nobody";
                window.AutoLockSeconds = 0;   // «бездействие» наступает сразу
                WaitDecided(f, 6000, "the dialog to be closed by auto-lock");
            });

            WaitUntil(delegate { return window.IsDisposed; }, 6000, "the main window to close");
            Check(window.LockRequested, "auto-lock is reported as a lock");
            Check(session.Data.Entries.Count == entries, "an unfinished dialog saves nothing");
            main = null;
        }

        /// <summary>
        /// Те же окна на английском языке. Отдельное хранилище с английскими данными: в его окнах
        /// не должно остаться ни одной русской буквы — ни в подписях, ни в меню, ни в сообщениях.
        /// </summary>
        private static void EnglishInterface()
        {
            const string password = "correct horse battery staple";
            string path = Path.Combine(workDir, EnglishVaultName);
            foreach (string file in new[] { path, path + ".bak", path + ".tmp" })
            {
                if (File.Exists(file)) File.Delete(file);
            }

            VaultSession previousSession = session;
            MainForm previousMain = main;
            session = null;
            main = null;
            L.Current = Language.English;
            try
            {
                using (var form = new UnlockForm(path))
                {
                    Drive<UnlockForm>(delegate { form.ShowDialog(); }, delegate(UnlockForm f)
                    {
                        Check(Find<Button>(f, "btnOk").Text == "Create vault", "caption of the create button: " + Find<Button>(f, "btnOk").Text);
                        Click(f, "btnOk");
                        Check(Find<Label>(f, "lblError").Text == "Enter the master password.", "validation message: " + Find<Label>(f, "lblError").Text);
                        Find<TextBox>(f, "txtPassword").Text = "abc";
                        CheckEnglish(f);
                        Find<TextBox>(f, "txtPassword").Text = password;
                        Find<TextBox>(f, "txtConfirm").Text = password;
                        CheckEnglish(f);
                        Shot(f, "en-01-create");
                        Click(f, "btnOk");
                        WaitDecided(f, 20000, "the vault to be created");
                    });
                    session = form.TakeSession();
                }
                Check(session != null, "the vault is created");

                OpenMain();
                SameList(new[] { "All entries", "No group" }, GroupNames(), "built-in rows of the tree");
                CheckEnglish(main);

                Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
                {
                    Check(box.Text == "New group", "dialog title: " + box.Text);
                    Click(box, "btnOk");
                    Check(Find<Label>(box, "lblError").Text == "Enter a group name.", "validation message: " + Find<Label>(box, "lblError").Text);
                    CheckEnglish(box);
                    Find<TextBox>(box, "txtName").Text = "Work";
                    Click(box, "btnOk");
                });
                // Новая группа выбрана, поэтому следующая предлагается внутри неё.
                Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
                {
                    Check(Find<ComboBox>(box, "cmbParent").SelectedItem.ToString() == "Work", "the new group goes inside the selected one");
                    Find<TextBox>(box, "txtName").Text = "Servers";
                    Click(box, "btnOk");
                });

                AddEnglishEntry("GitLab", "j.smith", "glpat-N8s2xQ4vT1", "Work");
                AddEnglishEntry("Build server", "build", "Bu!ld-Srv-2026", "Work / Servers");
                AddEnglishEntry("Mail\r\nPersonal mailbox", "john.smith@example.com", "Qw7!kPz#2026mail", "No group");

                SelectGroup("All entries");
                SelectEntries("GitLab");
                Check(StatusText("lblCount") == "Entries: 3", "counter: " + StatusText("lblCount"));
                SameList(new[] { "All entries", "Work", "> Servers", "No group" }, GroupNames(), "tree");
                CheckEnglish(main);
                Shot(main, "en-02-main");

                Drive<EntryForm>(delegate { ClickTool("toolbar", "btnEdit"); }, delegate(EntryForm f)
                {
                    Check(f.Text == "Edit entry", "dialog title: " + f.Text);
                    CheckEnglish(f);
                    Shot(f, "en-03-entry");
                    Click(f, "btnCancel");
                });

                Drive<MsgBox>(delegate { ClickTool("toolbar", "btnDelete"); }, delegate(MsgBox box)
                {
                    CheckEnglish(box);
                    Check(Find<Label>(box, "lblText").Text.Contains("GitLab"), "the question names the entry");
                    Click(box, "btnCancel");
                });

                SelectGroup("Work");
                Drive<MsgBox>(delegate { ClickTool("groupBar", "btnGroupDelete"); }, delegate(MsgBox box)
                {
                    string text = Find<Label>(box, "lblText").Text;
                    CheckEnglish(box);
                    Check(text.Contains("together with its subgroup") && text.Contains("2 entries will move to"), "group deletion is explained: " + text);
                    Click(box, "btnCancel");
                });

                Drive<MsgBox>(delegate { ClickTool("toolbar", "miAbout"); }, delegate(MsgBox box)
                {
                    string text = Find<Label>(box, "lblText").Text;
                    CheckEnglish(box);
                    Check(text.Contains("2 groups") && text.Contains("3 entries"), "contents are counted: " + text);
                    Click(box, "btnOk");
                });

                Drive<ChangePasswordForm>(delegate { main.ChangeMasterPassword(); }, delegate(ChangePasswordForm f)
                {
                    Click(f, "btnOk");
                    Check(Find<Label>(f, "lblError").Text == "Enter the current master password.", "validation message: " + Find<Label>(f, "lblError").Text);
                    CheckEnglish(f);
                    Click(f, "btnCancel");
                });

                // Меню «переместить» и сообщение о перемещении.
                SelectGroup("All entries");
                SelectEntries("GitLab");
                SameList(new[] { "Work", "Work / Servers", "-", "No group", "-", "New group…" }, MenuTexts(MoveMenu()), "move menu");
                MenuItem(MoveMenu(), "No group").PerformClick();
                Pump(30);
                Check(StatusText("lblMessage").StartsWith("Moved to") && StatusText("lblMessage").EndsWith(": 1 entry"), "status: " + StatusText("lblMessage"));
                CheckEnglish(main);

                main.Close();
                Pump(50);
                main = null;
                session.Dispose();
                session = null;

                // Вход в существующее хранилище: неверный пароль.
                using (var form = new UnlockForm(path))
                {
                    Drive<UnlockForm>(delegate { form.ShowDialog(); }, delegate(UnlockForm f)
                    {
                        Label error = Find<Label>(f, "lblError");
                        Check(Find<Button>(f, "btnOk").Text == "Open", "caption of the open button: " + Find<Button>(f, "btnOk").Text);
                        Find<TextBox>(f, "txtPassword").Text = password + "?";
                        Click(f, "btnOk");
                        WaitUntil(delegate { return !f.IsBusy; }, 20000, "the password check");
                        Check(error.Visible && error.Text.StartsWith("Wrong master password"), "wrong password is rejected: " + error.Text);
                        CheckEnglish(f);
                        Shot(f, "en-04-unlock");
                        Click(f, "btnCancel");
                    });
                }
            }
            finally
            {
                L.Current = Language.Russian;
                if (main != null && !main.IsDisposed) main.Close();
                if (session != null) session.Dispose();
                session = previousSession;
                main = previousMain;
            }
        }

        private static void AddEnglishEntry(string description, string login, string password, string group)
        {
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnAdd"); }, delegate(EntryForm f)
            {
                Check(f.Text == "New entry", "dialog title: " + f.Text);
                Find<TextBox>(f, "txtDescription").Text = description;
                Find<TextBox>(f, "txtLogin").Text = login;
                Find<TextBox>(f, "txtPassword").Text = password;
                SelectCombo(Find<ComboBox>(f, "cmbGroup"), group);
                Click(f, "btnOk");
            });
        }

        // =====================================================================
        //  Действия «как пользователь»
        // =====================================================================

        private static void OpenMain()
        {
            main = new MainForm(session);
            if (visible)
            {
                main.StartPosition = FormStartPosition.Manual;
                main.Location = new Point(Ui.S(40), Ui.S(30));
            }
            main.ClientSize = new Size(Ui.S(1040), Ui.S(620));
            main.Show();
            Pump(200);
        }

        private static void AddGroup(string name)
        {
            AddGroup(name, null);
        }

        /// <summary>
        /// Создаёт группу через окно «Новая группа». parent — путь к группе, в которую её вложить
        /// («Работа / Проекты»), или null для верхнего уровня.
        /// </summary>
        private static void AddGroup(string name, string parent)
        {
            Drive<GroupForm>(delegate { ClickTool("groupBar", "btnGroupAdd"); }, delegate(GroupForm box)
            {
                Find<TextBox>(box, "txtName").Text = name;
                SelectCombo(Find<ComboBox>(box, "cmbParent"), parent ?? "Верхний уровень");
                Click(box, "btnOk");
            });
        }

        private static void AddEntry(string description, string login, string password, string group)
        {
            Drive<EntryForm>(delegate { ClickTool("toolbar", "btnAdd"); }, delegate(EntryForm f)
            {
                Check(f.Text == "Новая запись", "dialog title");
                Find<TextBox>(f, "txtDescription").Text = description;
                Find<TextBox>(f, "txtLogin").Text = login;
                Find<TextBox>(f, "txtPassword").Text = password;
                SelectCombo(Find<ComboBox>(f, "cmbGroup"), group ?? "Без группы");
                Click(f, "btnOk");
            });
        }

        /// <summary>Выбирает строку дерева групп по пути: «Работа / Проекты», «Все записи».</summary>
        private static void SelectGroup(string path)
        {
            Tree.SelectedNode = GroupNode(path);
            Pump(30);
        }

        /// <summary>Щелчок мышью по стрелке, которая сворачивает и раскрывает ветку.</summary>
        private static void ClickArrow(string path)
        {
            GroupTree tree = Tree;
            Rectangle arrow = tree.ArrowBounds(GroupNode(path));
            int x = arrow.X + arrow.Width / 2;
            int y = arrow.Y + arrow.Height / 2;
            var position = (IntPtr)((y << 16) | (x & 0xFFFF));
            NativeMethods.SendMessage(tree.Handle, 0x0201, (IntPtr)1, position);    // WM_LBUTTONDOWN
            NativeMethods.SendMessage(tree.Handle, 0x0202, IntPtr.Zero, position);  // WM_LBUTTONUP
            Pump(30);
        }

        /// <summary>Вызывает закрытый метод главного окна без параметров.</summary>
        private static void InvokeMain(string method)
        {
            MethodInfo info = typeof(MainForm).GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic);
            info.Invoke(main, null);
            Pump(30);
        }

        private static void SelectEntries(params string[] titles)
        {
            ListView list = Entries;
            list.SelectedItems.Clear();
            foreach (string title in titles)
            {
                bool found = false;
                foreach (ListViewItem item in list.Items)
                {
                    if (item.Text == title)
                    {
                        item.Selected = true;
                        // Как при щелчке мышью: фокус переходит на выбранную строку.
                        if (list.SelectedItems.Count == 1) item.Focused = true;
                        found = true;
                        break;
                    }
                }
                if (!found) throw new Exception("no such entry in the list: " + title);
            }
            Pump(30);
        }

        private static void SetSearch(string text)
        {
            SearchBox.Text = text;
            Pump(30);
        }

        private static void SelectCombo(ComboBox combo, string text)
        {
            for (int i = 0; i < combo.Items.Count; i++)
            {
                if (combo.Items[i].ToString() == text)
                {
                    combo.SelectedIndex = i;
                    return;
                }
            }
            throw new Exception("no such choice: " + text);
        }

        private static void Click(Control root, string name)
        {
            Button button = Find<Button>(root, name);
            if (!button.Enabled || !button.Visible) throw new Exception("button is not available: " + name);
            button.PerformClick();
        }

        private static void ClickTool(string strip, string name)
        {
            ToolStripItem item = Tool(strip, name);
            if (!item.Enabled) throw new Exception("command is disabled: " + name);
            item.PerformClick();
            Pump(30);
        }

        /// <summary>Нажатие сочетания клавиш в главном окне.</summary>
        private static void Key(Keys keys)
        {
            object[] arguments = { Message.Create(main.Handle, 0x0100, IntPtr.Zero, IntPtr.Zero), keys };
            MethodInfo method = typeof(MainForm).GetMethod("ProcessCmdKey", BindingFlags.Instance | BindingFlags.NonPublic);
            try
            {
                method.Invoke(main, arguments);
            }
            catch (TargetInvocationException ex)
            {
                throw new Exception("shortcut " + keys + " failed: " + ex.InnerException.Message, ex.InnerException);
            }
            Pump(30);
        }

        /// <summary>
        /// Вызывает защищённый метод Windows Forms, который обычно вызывается самой системой
        /// (щелчок по заголовку столбца, нажатие клавиши, перетаскивание).
        /// </summary>
        private static void Raise(Control control, string method, EventArgs arguments)
        {
            for (Type type = control.GetType(); type != null; type = type.BaseType)
            {
                MethodInfo info = type.GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly);
                if (info != null)
                {
                    try
                    {
                        info.Invoke(control, new object[] { arguments });
                    }
                    catch (TargetInvocationException ex)
                    {
                        throw new Exception(method + " failed: " + ex.InnerException.Message, ex.InnerException);
                    }
                    Pump(30);
                    return;
                }
            }
            throw new Exception("method not found: " + method);
        }

        /// <summary>Событие перетаскивания над строкой дерева групп с указанным путём.</summary>
        private static DragEventArgs DragArgs(IDataObject data, string path)
        {
            GroupTree tree = Tree;
            Rectangle label = GroupNode(path).Bounds;
            for (int attempt = 0; label.Height == 0 && attempt < 100; attempt++)
            {
                // Дерево рассчитывает положение строк не сразу после обновления — дожидаемся.
                Pump(20);
                label = GroupNode(path).Bounds;
            }
            if (label.Height == 0) throw new Exception("the tree has no position for the row: " + path);
            Point screen = tree.PointToScreen(new Point(Ui.S(80), label.Y + label.Height / 2));
            return new DragEventArgs(data, 0, screen.X, screen.Y, DragDropEffects.Move, DragDropEffects.None);
        }

        /// <summary>Событие перетаскивания над свободным местом под деревом групп.</summary>
        private static DragEventArgs DragArgsBelowTree(IDataObject data)
        {
            GroupTree tree = Tree;
            Point screen = tree.PointToScreen(new Point(Ui.S(80), tree.ClientSize.Height - 3));
            return new DragEventArgs(data, 0, screen.X, screen.Y, DragDropEffects.Move, DragDropEffects.None);
        }

        private static ToolStripItemCollection MoveMenu()
        {
            // Меню заполняется в момент открытия; вызываем заполнение напрямую, не показывая меню.
            var button = (ToolStripDropDownButton)Tool("toolbar", "btnMove");
            MethodInfo populate = typeof(MainForm).GetMethod("PopulateMoveMenu", BindingFlags.Instance | BindingFlags.NonPublic);
            populate.Invoke(main, new object[] { button.DropDownItems });
            return button.DropDownItems;
        }

        private static ToolStripItem MenuItem(ToolStripItemCollection items, string text)
        {
            foreach (ToolStripItem item in items)
            {
                if (item.Text == text) return item;
            }
            throw new Exception("no such menu item: " + text);
        }

        private static string[] MenuTexts(ToolStripItemCollection items)
        {
            var texts = new List<string>();
            foreach (ToolStripItem item in items)
            {
                texts.Add(item is ToolStripSeparator ? "-" : item.Text);
            }
            return texts.ToArray();
        }

        // =====================================================================
        //  Чтение состояния окна
        // =====================================================================

        private static GroupTree Tree
        {
            get { return Find<GroupTree>(main, "treeGroups"); }
        }

        private static ListView Entries
        {
            get { return Find<ListView>(main, "lvEntries"); }
        }

        private static ToolStripTextBox SearchBox
        {
            get { return (ToolStripTextBox)Tool("toolbar", "txtSearch"); }
        }

        private static T Find<T>(Control root, string name) where T : Control
        {
            Control[] found = root.Controls.Find(name, true);
            if (found.Length == 0) throw new Exception("control not found: " + name);
            T typed = found[0] as T;
            if (typed == null) throw new Exception("control " + name + " has type " + found[0].GetType().Name);
            return typed;
        }

        private static ToolStripItem Tool(string strip, string name)
        {
            ToolStripItem[] found = Find<ToolStrip>(main, strip).Items.Find(name, true);
            if (found.Length == 0) throw new Exception("command not found: " + name);
            return found[0];
        }

        private static string StatusText(string name)
        {
            return Tool("status", name).Text;
        }

        /// <summary>Видимые строки дерева групп сверху вниз; уровень вложенности показан знаками «>».</summary>
        private static string[] GroupNames()
        {
            var names = new List<string>();
            CollectRows(Tree.Nodes, names);
            return names.ToArray();
        }

        private static void CollectRows(TreeNodeCollection nodes, List<string> names)
        {
            foreach (TreeNode node in nodes)
            {
                names.Add((node.Level > 0 ? new string('>', node.Level) + " " : "") + node.Text);
                if (node.IsExpanded) CollectRows(node.Nodes, names);
            }
        }

        /// <summary>Путь строки дерева: «Работа / Проекты».</summary>
        private static string PathOf(TreeNode node)
        {
            return node.Parent == null ? node.Text : PathOf(node.Parent) + " / " + node.Text;
        }

        private static TreeNode FindGroupNode(TreeNodeCollection nodes, string path)
        {
            foreach (TreeNode node in nodes)
            {
                if (PathOf(node) == path) return node;
                TreeNode nested = FindGroupNode(node.Nodes, path);
                if (nested != null) return nested;
            }
            return null;
        }

        private static bool HasGroup(string path)
        {
            return FindGroupNode(Tree.Nodes, path) != null;
        }

        private static TreeNode GroupNode(string path)
        {
            TreeNode node = FindGroupNode(Tree.Nodes, path);
            if (node == null) throw new Exception("no such group in the tree: " + path);
            return node;
        }

        private static string GroupId(string path)
        {
            return ((GroupItem)GroupNode(path).Tag).Id;
        }

        private static int GroupCount(string path)
        {
            return ((GroupItem)GroupNode(path).Tag).Count;
        }

        /// <summary>Путь выбранной строки дерева групп.</summary>
        private static string SelectedGroup()
        {
            TreeNode node = Tree.SelectedNode;
            return node == null ? "(nothing)" : PathOf(node);
        }

        private static string[] Titles()
        {
            return Column(0);
        }

        private static string[] Column(int column)
        {
            var values = new List<string>();
            foreach (ListViewItem item in Entries.Items) values.Add(item.SubItems[column].Text);
            return values.ToArray();
        }

        private static string[] SelectedTitles()
        {
            var values = new List<string>();
            foreach (ListViewItem item in Entries.SelectedItems) values.Add(item.Text);
            return values.ToArray();
        }

        private static string[] SelectedIds()
        {
            var values = new List<string>();
            foreach (ListViewItem item in Entries.SelectedItems) values.Add((string)item.Tag);
            return values.ToArray();
        }

        private static string Cell(string title, int column)
        {
            foreach (ListViewItem item in Entries.Items)
            {
                if (item.Text == title) return item.SubItems[column].Text;
            }
            throw new Exception("no such entry in the list: " + title);
        }

        private static string[] ComboItems(ComboBox combo)
        {
            var values = new List<string>();
            foreach (object item in combo.Items) values.Add(item.ToString());
            return values.ToArray();
        }

        private static Entry FindEntry(string description)
        {
            foreach (Entry entry in session.Data.Entries)
            {
                if (entry.Description == description) return entry;
            }
            return null;
        }

        private static int CountOnDisk()
        {
            using (VaultSession copy = VaultSession.Open(vaultPath, MasterPassword))
            {
                return copy.Data.Entries.Count + copy.Data.Groups.Count;
            }
        }

        private static int ReadInt32(IDataObject data, string format)
        {
            var stream = data.GetData(format) as Stream;
            if (stream == null) return -1;
            byte[] buffer = new byte[4];
            stream.Position = 0;
            return stream.Read(buffer, 0, 4) == 4 ? BitConverter.ToInt32(buffer, 0) : -1;
        }

        // =====================================================================
        //  Инфраструктура
        // =====================================================================

        /// <summary>
        /// Выполняет действие open, которое открывает модальный диалог типа T и ждёт его закрытия,
        /// а когда диалог появится — запускает для него сценарий script. Если сценарий оставил
        /// диалог открытым, он закрывается отменой.
        /// </summary>
        private static void Drive<T>(Action open, Action<T> script) where T : Form
        {
            Exception error = null;
            bool handled = false;
            int waited = 0;

            var timer = new FormsTimer();
            timer.Interval = 25;
            timer.Tick += delegate
            {
                T dialog = null;
                FormCollection forms = Application.OpenForms;
                for (int i = forms.Count - 1; i >= 0; i--)
                {
                    T candidate = forms[i] as T;
                    if (candidate != null && candidate.Visible && !driven.Contains(candidate))
                    {
                        dialog = candidate;
                        break;
                    }
                }
                if (dialog == null)
                {
                    waited += timer.Interval;
                    return;
                }

                timer.Stop();
                handled = true;
                driven.Add(dialog);
                try
                {
                    Pump(40);
                    script(dialog);
                }
                catch (Exception ex)
                {
                    error = ex;
                }
                finally
                {
                    // Сценарий не нажал ни «ОК», ни «Отмена» (например, проверял сообщение об ошибке
                    // и вышел) — закрываем диалог отменой, иначе прогон застрянет.
                    if (!dialog.IsDisposed && dialog.Visible && dialog.DialogResult == DialogResult.None)
                    {
                        WaitUntilQuiet(dialog);
                        if (!dialog.IsDisposed && dialog.Visible && dialog.DialogResult == DialogResult.None)
                        {
                            dialog.DialogResult = DialogResult.Cancel;
                            dialog.Close();
                        }
                    }
                }
            };

            timer.Start();
            try
            {
                open();
            }
            finally
            {
                timer.Stop();
                timer.Dispose();
            }

            if (error != null) throw new Exception(error.Message, error);
            if (!handled) throw new Exception("dialog " + typeof(T).Name + " did not appear (waited " + waited + " ms)");
            Pump(40);
        }

        private static void WaitUntilQuiet(Form dialog)
        {
            var busyDialog = dialog as DialogForm;
            if (busyDialog == null) return;
            Stopwatch watch = Stopwatch.StartNew();
            while (busyDialog.IsBusy && watch.ElapsedMilliseconds < 30000)
            {
                Application.DoEvents();
                Thread.Sleep(10);
            }
        }

        /// <summary>
        /// Ждёт, пока диалог «решит закрыться». Модальное окно исчезает с экрана только когда
        /// управление вернётся в его цикл сообщений, то есть после выхода из сценария, поэтому
        /// признаком служит выставленный результат, а не видимость окна.
        /// </summary>
        private static void WaitDecided(Form dialog, int timeoutMs, string what)
        {
            WaitUntil(delegate { return dialog.IsDisposed || !dialog.Visible || dialog.DialogResult != DialogResult.None; }, timeoutMs, what);
        }

        private static void WaitUntil(Func<bool> condition, int timeoutMs, string what)
        {
            Stopwatch watch = Stopwatch.StartNew();
            while (!condition())
            {
                if (watch.ElapsedMilliseconds > timeoutMs) throw new Exception("timed out waiting for " + what);
                Application.DoEvents();
                Thread.Sleep(10);
            }
            Pump(20);
        }

        private static void Pump(int milliseconds)
        {
            Stopwatch watch = Stopwatch.StartNew();
            do
            {
                Application.DoEvents();
                Thread.Sleep(5);
            }
            while (watch.ElapsedMilliseconds < milliseconds);
        }

        private static void Run(string name, Action test)
        {
            asyncFailure = null;
            Exception failure = null;
            try
            {
                test();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            if (failure == null && asyncFailure != null) failure = asyncFailure;

            if (failure == null)
            {
                passed++;
                Console.WriteLine("ok    " + name);
            }
            else
            {
                failed++;
                Console.WriteLine("FAIL  " + name);
                Console.WriteLine("      " + failure.GetType().Name + ": " + failure.Message);
                Exception inner = failure.InnerException ?? failure;
                string[] trace = (inner.StackTrace ?? "").Split('\n');
                for (int i = 0; i < trace.Length && i < 6; i++)
                {
                    Console.WriteLine("      " + trace[i].Trim());
                }
            }
        }

        private static void Check(bool condition, string what)
        {
            if (!condition) throw new Exception("check failed: " + what);
        }

        private static void SameList(string[] expected, string[] actual, string what)
        {
            SameList(expected, actual, what, false);
        }

        private static void SameList(string[] expected, string[] actual, string what, bool anyOrder)
        {
            string[] left = anyOrder ? SortedCopy(expected) : expected;
            string[] right = anyOrder ? SortedCopy(actual) : actual;
            bool same = left.Length == right.Length;
            for (int i = 0; same && i < left.Length; i++)
            {
                if (left[i] != right[i]) same = false;
            }
            if (!same)
            {
                throw new Exception(what + ": expected [" + string.Join(" | ", expected) + "], got [" + string.Join(" | ", actual) + "]");
            }
        }

        // ---------- Проверка перевода ----------

        /// <summary>
        /// В окне, его меню и списках не должно быть ни одной русской буквы. Строки с путём
        /// к файлу хранилища не проверяются: папка, где идут тесты, может называться как угодно.
        /// </summary>
        private static void CheckEnglish(Form form)
        {
            var texts = new List<string>();
            CollectTexts(form, texts);
            Check(texts.Count >= 3, "texts of " + form.Name + " are collected: " + texts.Count);

            foreach (string text in texts)
            {
                foreach (string line in text.Split('\n'))
                {
                    if (line.Contains(EnglishVaultName)) continue;
                    foreach (char c in line)
                    {
                        if (c >= 0x0400 && c <= 0x04FF)
                        {
                            throw new Exception("russian text in the English interface of " + form.Name + ": " + line.Trim());
                        }
                    }
                }
            }
        }

        private static void CollectTexts(Control control, List<string> texts)
        {
            AddText(texts, control.Text);
            AddText(texts, control.AccessibleName);

            var strip = control as ToolStrip;
            if (strip != null) CollectItemTexts(strip.Items, texts);
            if (control.ContextMenuStrip != null) CollectItemTexts(control.ContextMenuStrip.Items, texts);

            var list = control as ListView;
            if (list != null)
            {
                foreach (ColumnHeader column in list.Columns) AddText(texts, column.Text);
                foreach (ListViewItem item in list.Items)
                {
                    foreach (ListViewItem.ListViewSubItem cell in item.SubItems) AddText(texts, cell.Text);
                }
            }

            var tree = control as TreeView;
            if (tree != null) CollectNodeTexts(tree.Nodes, texts);

            var combo = control as ComboBox;
            if (combo != null)
            {
                foreach (object item in combo.Items) AddText(texts, item.ToString());
            }

            foreach (Control child in control.Controls) CollectTexts(child, texts);
        }

        private static void CollectItemTexts(ToolStripItemCollection items, List<string> texts)
        {
            foreach (ToolStripItem item in items)
            {
                AddText(texts, item.Text);
                AddText(texts, item.ToolTipText);
                AddText(texts, item.AccessibleName);
                var dropDown = item as ToolStripDropDownItem;
                if (dropDown != null) CollectItemTexts(dropDown.DropDownItems, texts);
            }
        }

        private static void CollectNodeTexts(TreeNodeCollection nodes, List<string> texts)
        {
            foreach (TreeNode node in nodes)
            {
                AddText(texts, node.Text);
                CollectNodeTexts(node.Nodes, texts);
            }
        }

        private static void AddText(List<string> texts, string text)
        {
            if (!string.IsNullOrEmpty(text)) texts.Add(text);
        }

        private static string[] SortedCopy(string[] values)
        {
            var copy = (string[])values.Clone();
            Array.Sort(copy, StringComparer.Ordinal);
            return copy;
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }

        // ---------- Снимки окон ----------

        private static void Shot(Form form, string name)
        {
            Pump(80);
            RECT bounds;
            GetWindowRect(form.Handle, out bounds);
            int width = bounds.Right - bounds.Left;
            int height = bounds.Bottom - bounds.Top;
            if (width <= 0 || height <= 0) return;

            using (var bitmap = new Bitmap(width, height, PixelFormat.Format32bppArgb))
            {
                using (Graphics g = Graphics.FromImage(bitmap))
                {
                    g.Clear(Color.White);
                    IntPtr hdc = g.GetHdc();
                    try
                    {
                        // 2 = PW_RENDERFULLCONTENT: снимок с экрана как есть; 0 — окно рисует себя само
                        // (годится и для окон за краем экрана).
                        PrintWindow(form.Handle, hdc, visible ? 2 : 0);
                    }
                    finally
                    {
                        g.ReleaseHdc(hdc);
                    }
                }

                Rectangle crop = new Rectangle(0, 0, width, height);
                RECT frame;
                if (visible && DwmGetWindowAttribute(form.Handle, 9, out frame, Marshal.SizeOf(typeof(RECT))) == 0)
                {
                    // Без невидимых полей вокруг окна, которые нужны только для захвата мышью.
                    crop = Rectangle.Intersect(crop, new Rectangle(frame.Left - bounds.Left, frame.Top - bounds.Top, frame.Right - frame.Left, frame.Bottom - frame.Top));
                }
                using (Bitmap cropped = bitmap.Clone(crop, PixelFormat.Format32bppArgb))
                {
                    cropped.Save(Path.Combine(shotDir, name + ".png"), ImageFormat.Png);
                }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PrintWindow(IntPtr hwnd, IntPtr hdc, int flags);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);

        [DllImport("dwmapi.dll")]
        private static extern int DwmGetWindowAttribute(IntPtr hwnd, int attribute, out RECT value, int size);
    }
}
