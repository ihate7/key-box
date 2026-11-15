using System;
using System.Collections.Generic;
using KeyBox.Crypto;

namespace KeyBox.Vault
{
    /// <summary>Запись, прочитанная из чужого файла.</summary>
    internal sealed class ImportedEntry
    {
        public string Title = "";
        public string Url = "";
        public string Login = "";
        public string Password = "";
        public string Notes = "";
        public string Group = "";
        public string Totp = "";
    }

    /// <summary>Что удалось прочитать из файла — ещё до того, как что-либо добавлено в хранилище.</summary>
    internal sealed class ImportPlan
    {
        public readonly List<ImportedEntry> Entries = new List<ImportedEntry>();

        /// <summary>Строки, в которых не оказалось ничего пригодного.</summary>
        public int Skipped;

        /// <summary>Почему файл не удалось понять; null, если всё в порядке.</summary>
        public string Error;
    }

    internal sealed class ImportResult
    {
        /// <summary>Группа, в которую сложено импортированное.</summary>
        public Group Root;

        public int Entries;
        public int Groups;
    }

    /// <summary>
    /// Перенос записей из других программ и в другие программы через CSV. Столбцы узнаются по
    /// названиям в строке заголовков, поэтому подходят файлы Chrome, Edge, Firefox, Bitwarden,
    /// KeePassXC и другие с понятными заголовками.
    /// </summary>
    internal static class VaultTransfer
    {
        /// <summary>Столбцы экспорта: первые пять — как у Chrome и Edge, поэтому файл понимают и другие программы.</summary>
        public static readonly string[] ExportHeader = { "name", "url", "username", "password", "note", "group", "totp" };

        private static readonly string[] TitleNames = { "name", "title", "account", "site name" };
        private static readonly string[] UrlNames = { "url", "website", "web site", "login_uri", "uri", "login uri" };
        private static readonly string[] LoginNames = { "username", "user name", "login name", "login", "login_username", "user", "email" };
        private static readonly string[] PasswordNames = { "password", "login_password", "pass" };
        private static readonly string[] NotesNames = { "note", "notes", "comment", "comments", "extra" };
        private static readonly string[] GroupNames = { "group", "folder", "grouping", "category" };
        private static readonly string[] TotpNames = { "totp", "login_totp", "otpauth", "otp", "otpsecret" };

        private static readonly char[] PathSeparators = { '/', '\\' };

        // ---------- Импорт ----------

        /// <summary>Разбирает текст CSV-файла. В хранилище при этом ничего не меняется.</summary>
        public static ImportPlan ReadCsv(string text)
        {
            var plan = new ImportPlan();
            List<string[]> rows = Csv.Parse(text);
            if (rows.Count == 0)
            {
                plan.Error = L.T("Файл пуст.", "The file is empty.");
                return plan;
            }

            string[] header = rows[0];
            int title = Find(header, TitleNames);
            int url = Find(header, UrlNames);
            int login = Find(header, LoginNames);
            int password = Find(header, PasswordNames);
            int notes = Find(header, NotesNames);
            int group = Find(header, GroupNames);
            int totp = Find(header, TotpNames);

            if (password < 0 || (title < 0 && url < 0 && login < 0))
            {
                plan.Error = L.T(
                    "Не удалось понять столбцы файла. В первой строке должны быть названия столбцов: password и хотя бы один из name, url, username. " +
                    "Такие файлы выгружают Chrome, Edge, Firefox, Bitwarden и KeePassXC.",
                    "The columns of the file were not recognised. The first line must name the columns: password and at least one of name, url, username. " +
                    "Chrome, Edge, Firefox, Bitwarden and KeePassXC export such files.");
                return plan;
            }

            for (int i = 1; i < rows.Count; i++)
            {
                string[] row = rows[i];
                var entry = new ImportedEntry();
                entry.Title = Cell(row, title).Trim();
                entry.Url = Cell(row, url).Trim();
                entry.Login = Cell(row, login).Trim();
                entry.Password = Cell(row, password);
                entry.Notes = Cell(row, notes).Replace("\r\n", "\n").Replace('\r', '\n').Trim();
                entry.Group = Cell(row, group).Trim();
                entry.Totp = Cell(row, totp).Trim();

                bool empty = entry.Title.Length == 0 && entry.Url.Length == 0 && entry.Login.Length == 0 &&
                             entry.Password.Length == 0 && entry.Notes.Length == 0;
                if (empty || entry.Password.Length > VaultData.MaxPasswordLength || entry.Login.Length > VaultData.MaxLoginLength)
                {
                    plan.Skipped++;
                    continue;
                }
                plan.Entries.Add(entry);
            }
            return plan;
        }

        /// <summary>
        /// Добавляет прочитанные записи в хранилище. Всё складывается в новую группу верхнего
        /// уровня; группы из файла становятся её подгруппами.
        /// </summary>
        public static ImportResult Import(VaultData data, ImportPlan plan, string rootName)
        {
            if (data == null) throw new ArgumentNullException("data");
            if (plan == null) throw new ArgumentNullException("plan");

            var result = new ImportResult();
            result.Root = data.AddGroup(UniqueName(data, rootName));

            var groups = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (ImportedEntry imported in plan.Entries)
            {
                var fields = new EntryFields();
                fields.GroupId = ResolveGroup(data, result, groups, imported.Group);
                fields.Login = imported.Login;
                fields.Password = imported.Password;
                fields.Url = Limit(imported.Url, VaultData.MaxUrlLength);

                string title = imported.Title.Length > 0 ? imported.Title : HostOf(imported.Url);
                string description = imported.Notes.Length == 0 ? title : (title.Length == 0 ? imported.Notes : title + "\n" + imported.Notes);

                // Ключ одноразовых кодов, который не удалось разобрать, не теряется: он уходит в описание.
                if (imported.Totp.Length > 0)
                {
                    if (imported.Totp.Length <= VaultData.MaxTotpLength && Totp.Parse(imported.Totp) != null) fields.Totp = imported.Totp;
                    else description += (description.Length > 0 ? "\n" : "") + "TOTP: " + imported.Totp;
                }

                if (string.IsNullOrWhiteSpace(description) && string.IsNullOrWhiteSpace(fields.Login))
                {
                    description = L.T("(без названия)", "(untitled)");
                }
                fields.Description = Limit(description, VaultData.MaxDescriptionLength);

                data.AddEntry(fields);
                result.Entries++;
            }
            return result;
        }

        /// <summary>Группа записи: путь из файла («Работа/Серверы») превращается в подгруппы импортной группы.</summary>
        private static string ResolveGroup(VaultData data, ImportResult result, Dictionary<string, string> groups, string path)
        {
            string[] parts = (path ?? "").Split(PathSeparators, StringSplitOptions.RemoveEmptyEntries);
            var names = new List<string>();
            foreach (string part in parts)
            {
                string name = Limit(part.Trim(), VaultData.MaxGroupNameLength);
                if (name.Length > 0) names.Add(name);
            }

            // Импортная группа занимает один уровень; всё, что глубже допустимого, остаётся на последнем уровне.
            int levels = Math.Min(names.Count, VaultData.MaxGroupDepth - 1);
            string parentId = result.Root.Id;
            string key = "";
            for (int i = 0; i < levels; i++)
            {
                key += "/" + names[i];
                string id;
                if (!groups.TryGetValue(key, out id))
                {
                    id = data.AddGroup(names[i], parentId).Id;
                    groups[key] = id;
                    result.Groups++;
                }
                parentId = id;
            }
            return parentId;
        }

        private static string UniqueName(VaultData data, string wanted)
        {
            string name = Limit((wanted ?? "").Trim(), VaultData.MaxGroupNameLength - 6);
            if (name.Length == 0) name = L.T("Импорт", "Import");

            string candidate = name;
            for (int number = 2; data.ValidateGroupName(candidate, null, null) != null && number < 1000; number++)
            {
                candidate = name + " (" + number + ")";
            }
            return candidate;
        }

        private static int Find(string[] header, string[] names)
        {
            for (int i = 0; i < header.Length; i++)
            {
                string cell = (header[i] ?? "").Trim().ToLowerInvariant();
                if (Array.IndexOf(names, cell) >= 0) return i;
            }
            return -1;
        }

        private static string Cell(string[] row, int index)
        {
            return index >= 0 && index < row.Length ? (row[index] ?? "") : "";
        }

        private static string Limit(string value, int length)
        {
            value = value ?? "";
            return value.Length > length ? value.Substring(0, length) : value;
        }

        /// <summary>Имя сайта из адреса — название для записи, у которой в файле названия нет.</summary>
        private static string HostOf(string url)
        {
            string value = (url ?? "").Trim();
            if (value.Length == 0) return "";

            Uri uri;
            string candidate = value.IndexOf("://", StringComparison.Ordinal) < 0 ? "https://" + value : value;
            if (Uri.TryCreate(candidate, UriKind.Absolute, out uri) && !string.IsNullOrEmpty(uri.Host)) return uri.Host;
            return value;
        }

        // ---------- Экспорт ----------

        /// <summary>
        /// Все записи (кроме лежащих в корзине) в виде CSV. Первая строка описания становится
        /// названием, остальные — заметкой; группа пишется полным путём через «/».
        /// </summary>
        public static string ToCsv(VaultData data)
        {
            if (data == null) throw new ArgumentNullException("data");

            var rows = new List<string[]>();
            rows.Add(ExportHeader);
            foreach (Entry entry in data.Entries)
            {
                if (entry.IsDeleted) continue;

                string description = entry.Description ?? "";
                int lineEnd = description.IndexOf('\n');
                string title = lineEnd < 0 ? description : description.Substring(0, lineEnd);
                string note = lineEnd < 0 ? "" : description.Substring(lineEnd + 1);
                string path = data.GroupPath(entry.GroupId);

                rows.Add(new[]
                {
                    title,
                    entry.Url ?? "",
                    entry.Login ?? "",
                    entry.Password ?? "",
                    note,
                    path == null ? "" : path.Replace(VaultData.PathSeparator, "/"),
                    entry.Totp ?? ""
                });
            }
            return Csv.Write(rows);
        }
    }
}
