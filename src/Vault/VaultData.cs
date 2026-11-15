using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using KeyBox.Crypto;

namespace KeyBox.Vault
{
    /// <summary>Ошибка в данных, введённых пользователем. Текст можно показывать как есть.</summary>
    internal sealed class ValidationException : Exception
    {
        public ValidationException(string message) : base(message) { }
    }

    /// <summary>Группа паролей. Группы можно вкладывать друг в друга.</summary>
    [DataContract]
    internal sealed class Group
    {
        [DataMember(Name = "id", Order = 0)]
        public string Id { get; set; }

        [DataMember(Name = "name", Order = 1)]
        public string Name { get; set; }

        /// <summary>
        /// Идентификатор группы, в которую вложена эта; null — группа верхнего уровня.
        /// У групп верхнего уровня поле в файл не пишется.
        /// </summary>
        [DataMember(Name = "parentId", Order = 2, EmitDefaultValue = false)]
        public string ParentId { get; set; }

        /// <summary>
        /// Время последнего изменения группы (название, место в дереве), UTC, ISO 8601.
        /// Нужно при объединении двух копий хранилища: побеждает более позднее изменение.
        /// </summary>
        [DataMember(Name = "changed", Order = 3, EmitDefaultValue = false)]
        public string Changed { get; set; }
    }

    /// <summary>Запись: логин, пароль, описание и группа, в которой она лежит.</summary>
    [DataContract]
    internal sealed class Entry
    {
        [DataMember(Name = "id", Order = 0)]
        public string Id { get; set; }

        /// <summary>Идентификатор группы; null — запись без группы.</summary>
        [DataMember(Name = "groupId", Order = 1)]
        public string GroupId { get; set; }

        [DataMember(Name = "login", Order = 2)]
        public string Login { get; set; }

        [DataMember(Name = "password", Order = 3)]
        public string Password { get; set; }

        /// <summary>Описание; переводы строк хранятся как "\n".</summary>
        [DataMember(Name = "description", Order = 4)]
        public string Description { get; set; }

        /// <summary>Время создания, UTC, ISO 8601.</summary>
        [DataMember(Name = "created", Order = 5)]
        public string Created { get; set; }

        /// <summary>Время последнего изменения логина, пароля или описания, UTC, ISO 8601.</summary>
        [DataMember(Name = "modified", Order = 6)]
        public string Modified { get; set; }

        /// <summary>Адрес сайта или сервиса; null, если не задан.</summary>
        [DataMember(Name = "url", Order = 7, EmitDefaultValue = false)]
        public string Url { get; set; }

        /// <summary>
        /// Ключ одноразовых кодов (TOTP): строка Base32 или ссылка otpauth://; null, если не задан.
        /// </summary>
        [DataMember(Name = "totp", Order = 8, EmitDefaultValue = false)]
        public string Totp { get; set; }

        /// <summary>Прежние пароли записи, от нового к старому; null, если пароль не менялся.</summary>
        [DataMember(Name = "history", Order = 9, EmitDefaultValue = false)]
        public List<PasswordRecord> History { get; set; }

        /// <summary>Когда запись удалена в корзину, UTC, ISO 8601; null — запись не удалена.</summary>
        [DataMember(Name = "deleted", Order = 10, EmitDefaultValue = false)]
        public string Deleted { get; set; }

        /// <summary>
        /// Время последнего изменения любого рода (содержимое, группа, корзина), UTC, ISO 8601.
        /// Нужно при объединении двух копий хранилища: побеждает более позднее изменение.
        /// </summary>
        [DataMember(Name = "changed", Order = 11, EmitDefaultValue = false)]
        public string Changed { get; set; }

        /// <summary>true, если запись лежит в корзине.</summary>
        public bool IsDeleted
        {
            get { return !string.IsNullOrEmpty(Deleted); }
        }
    }

    /// <summary>Прежний пароль записи.</summary>
    [DataContract]
    internal sealed class PasswordRecord
    {
        [DataMember(Name = "password", Order = 0)]
        public string Password { get; set; }

        /// <summary>Когда этот пароль был заменён следующим, UTC, ISO 8601.</summary>
        [DataMember(Name = "replaced", Order = 1)]
        public string Replaced { get; set; }
    }

    /// <summary>
    /// След окончательно удалённой записи или группы. При объединении двух копий хранилища
    /// он не даёт удалённому «воскреснуть» из той копии, где удаления ещё не было.
    /// </summary>
    [DataContract]
    internal sealed class Tombstone
    {
        [DataMember(Name = "id", Order = 0)]
        public string Id { get; set; }

        [DataMember(Name = "when", Order = 1)]
        public string When { get; set; }
    }

    /// <summary>Настройки, которые хранятся внутри хранилища и переезжают вместе с ним.</summary>
    [DataContract]
    internal sealed class VaultSettings
    {
        public const int MinPasswordLength = 6;
        public const int MaxPasswordLength = 128;
        public const int MaxAutoLockMinutes = 600;
        public const int MinClipboardSeconds = 5;
        public const int MaxClipboardSeconds = 600;

        /// <summary>"ru", "en" или null — как в системе.</summary>
        [DataMember(Name = "language", Order = 0, EmitDefaultValue = false)]
        public string Language { get; set; }

        /// <summary>Через сколько минут бездействия блокировать хранилище; 0 — не блокировать.</summary>
        [DataMember(Name = "autoLockMinutes", Order = 1)]
        public int AutoLockMinutes { get; set; }

        /// <summary>Через сколько секунд очищать буфер обмена после копирования.</summary>
        [DataMember(Name = "clipboardSeconds", Order = 2)]
        public int ClipboardSeconds { get; set; }

        [DataMember(Name = "passwordLength", Order = 3)]
        public int PasswordLength { get; set; }

        [DataMember(Name = "passwordUpper", Order = 4)]
        public bool PasswordUpper { get; set; }

        [DataMember(Name = "passwordLower", Order = 5)]
        public bool PasswordLower { get; set; }

        [DataMember(Name = "passwordDigits", Order = 6)]
        public bool PasswordDigits { get; set; }

        [DataMember(Name = "passwordSymbols", Order = 7)]
        public bool PasswordSymbols { get; set; }

        /// <summary>Не использовать похожие друг на друга символы: O и 0, l и 1.</summary>
        [DataMember(Name = "passwordNoLookAlikes", Order = 8)]
        public bool PasswordNoLookAlikes { get; set; }

        /// <summary>Нажимать Enter после автоввода логина и пароля.</summary>
        [DataMember(Name = "autoTypeEnter", Order = 9)]
        public bool AutoTypeEnter { get; set; }

        /// <summary>Время последнего изменения настроек, UTC, ISO 8601 (для объединения копий).</summary>
        [DataMember(Name = "changed", Order = 10, EmitDefaultValue = false)]
        public string Changed { get; set; }

        public static VaultSettings Defaults()
        {
            var settings = new VaultSettings();
            settings.AutoLockMinutes = 5;
            settings.ClipboardSeconds = 30;
            settings.PasswordLength = 20;
            settings.PasswordUpper = true;
            settings.PasswordLower = true;
            settings.PasswordDigits = true;
            settings.PasswordSymbols = true;
            settings.PasswordNoLookAlikes = true;
            settings.AutoTypeEnter = true;
            return settings;
        }

        public VaultSettings Clone()
        {
            return (VaultSettings)MemberwiseClone();
        }

        /// <summary>true, если все значения (кроме времени изменения) совпадают.</summary>
        public bool SameAs(VaultSettings other)
        {
            return other != null &&
                   (Language ?? "") == (other.Language ?? "") &&
                   AutoLockMinutes == other.AutoLockMinutes &&
                   ClipboardSeconds == other.ClipboardSeconds &&
                   PasswordLength == other.PasswordLength &&
                   PasswordUpper == other.PasswordUpper &&
                   PasswordLower == other.PasswordLower &&
                   PasswordDigits == other.PasswordDigits &&
                   PasswordSymbols == other.PasswordSymbols &&
                   PasswordNoLookAlikes == other.PasswordNoLookAlikes &&
                   AutoTypeEnter == other.AutoTypeEnter;
        }

        /// <summary>Приводит значения, прочитанные из файла, к допустимым границам.</summary>
        public void Normalize()
        {
            if (Language != "ru" && Language != "en") Language = null;
            AutoLockMinutes = Math.Max(0, Math.Min(MaxAutoLockMinutes, AutoLockMinutes));
            ClipboardSeconds = Math.Max(MinClipboardSeconds, Math.Min(MaxClipboardSeconds, ClipboardSeconds));
            PasswordLength = Math.Max(MinPasswordLength, Math.Min(MaxPasswordLength, PasswordLength));
            if (!PasswordUpper && !PasswordLower && !PasswordDigits && !PasswordSymbols)
            {
                PasswordUpper = true;
                PasswordLower = true;
                PasswordDigits = true;
            }
        }
    }

    /// <summary>Поля записи, которые вводит пользователь.</summary>
    internal sealed class EntryFields
    {
        public string GroupId;
        public string Login;
        public string Password;
        public string Description;
        public string Url;
        public string Totp;
    }

    internal enum FilterKind
    {
        All,
        Ungrouped,
        Group,
        Trash
    }

    /// <summary>Какую часть записей показывать: все, без группы, одну группу или корзину.</summary>
    internal struct GroupFilter
    {
        public readonly FilterKind Kind;
        public readonly string GroupId;

        private GroupFilter(FilterKind kind, string groupId)
        {
            Kind = kind;
            GroupId = groupId;
        }

        public static GroupFilter All
        {
            get { return new GroupFilter(FilterKind.All, null); }
        }

        public static GroupFilter Ungrouped
        {
            get { return new GroupFilter(FilterKind.Ungrouped, null); }
        }

        /// <summary>Корзина: записи, удалённые пользователем, но ещё не стёртые окончательно.</summary>
        public static GroupFilter Trash
        {
            get { return new GroupFilter(FilterKind.Trash, null); }
        }

        public static GroupFilter ForGroup(string groupId)
        {
            return new GroupFilter(FilterKind.Group, groupId);
        }

        /// <summary>Фильтр, под который попадает запись с указанной группой.</summary>
        public static GroupFilter ForEntryGroup(string groupId)
        {
            return string.IsNullOrEmpty(groupId) ? Ungrouped : ForGroup(groupId);
        }

        public bool Matches(Entry entry)
        {
            // Удалённые записи видны только в корзине, а в корзине нет ничего другого.
            if (entry.IsDeleted || Kind == FilterKind.Trash) return entry.IsDeleted && Kind == FilterKind.Trash;

            switch (Kind)
            {
                case FilterKind.Ungrouped:
                    return string.IsNullOrEmpty(entry.GroupId);
                case FilterKind.Group:
                    return entry.GroupId == GroupId;
                default:
                    return true;
            }
        }

        public bool SameAs(GroupFilter other)
        {
            return Kind == other.Kind && (Kind != FilterKind.Group || GroupId == other.GroupId);
        }
    }

    /// <summary>
    /// Содержимое хранилища: группы и записи. Все операции над данными собраны здесь,
    /// чтобы их можно было проверять без интерфейса.
    /// </summary>
    [DataContract]
    internal sealed class VaultData
    {
        /// <summary>
        /// Версия структуры данных. 1 — группы одним списком; 2 — группы могут быть вложенными;
        /// 3 — у записей есть адрес сайта, одноразовые коды, история паролей и корзина, у хранилища —
        /// настройки. Файл помечается наименьшей версией, которой хватает для его содержимого:
        /// так хранилище без новых возможностей по-прежнему открывается прежними версиями программы,
        /// а с новыми они честно откажутся его открывать, вместо того чтобы потерять данные.
        /// </summary>
        public const int CurrentVersion = 3;

        public const int MaxGroupNameLength = 100;

        /// <summary>Наибольшая глубина вложенности групп (1 — только верхний уровень).</summary>
        public const int MaxGroupDepth = 8;

        /// <summary>Разделитель в пути к группе: «Работа / Проекты».</summary>
        public const string PathSeparator = " / ";

        public const int MaxLoginLength = 1000;
        public const int MaxPasswordLength = 1000;
        public const int MaxDescriptionLength = 10000;
        public const int MaxUrlLength = 2000;
        public const int MaxTotpLength = 1000;

        /// <summary>Сколько прежних паролей хранится у записи.</summary>
        public const int MaxHistory = 10;

        /// <summary>Сколько дней удалённая запись лежит в корзине, прежде чем стереться окончательно.</summary>
        public const int TrashDays = 30;

        private static readonly char[] Whitespace = { ' ', '\t', '\r', '\n' };

        [DataMember(Name = "version", Order = 0)]
        public int Version { get; set; }

        [DataMember(Name = "groups", Order = 1)]
        public List<Group> Groups { get; set; }

        [DataMember(Name = "entries", Order = 2)]
        public List<Entry> Entries { get; set; }

        /// <summary>Настройки; null — всё по умолчанию.</summary>
        [DataMember(Name = "settings", Order = 3, EmitDefaultValue = false)]
        public VaultSettings Settings { get; set; }

        /// <summary>Следы окончательно удалённых записей и групп (для объединения копий); может быть null.</summary>
        [DataMember(Name = "removed", Order = 4, EmitDefaultValue = false)]
        public List<Tombstone> Removed { get; set; }

        public static VaultData CreateEmpty()
        {
            var data = new VaultData();
            data.Groups = new List<Group>();
            data.Entries = new List<Entry>();
            data.Version = data.RequiredVersion();
            return data;
        }

        // ---------- Группы ----------

        public Group FindGroup(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            foreach (Group group in Groups)
            {
                if (group.Id == id) return group;
            }
            return null;
        }

        /// <summary>Название группы или null, если группы нет (запись без группы).</summary>
        public string GroupName(string id)
        {
            Group group = FindGroup(id);
            return group == null ? null : group.Name;
        }

        /// <summary>Путь к группе от верхнего уровня: «Работа / Проекты». null, если группы нет.</summary>
        public string GroupPath(string id)
        {
            var names = new List<string>();
            Group group = FindGroup(id);
            for (int guard = 0; group != null && guard <= Groups.Count; guard++)
            {
                names.Insert(0, group.Name);
                group = FindGroup(group.ParentId);
            }
            return names.Count == 0 ? null : string.Join(PathSeparator, names.ToArray());
        }

        /// <summary>Группы, вложенные непосредственно в указанную (null — группы верхнего уровня).</summary>
        public List<Group> ChildrenOf(string parentId)
        {
            string parent = NormalizeId(parentId);
            var result = new List<Group>();
            foreach (Group group in Groups)
            {
                if (group.ParentId == parent) result.Add(group);
            }
            return result;
        }

        /// <summary>Все группы, вложенные в указанную на любой глубине.</summary>
        public List<Group> DescendantsOf(string id)
        {
            var result = new List<Group>();
            if (!string.IsNullOrEmpty(id)) CollectDescendants(id, result, 0);
            return result;
        }

        private void CollectDescendants(string parentId, List<Group> result, int depth)
        {
            if (depth > Groups.Count) return; // защита от зацикленных данных
            foreach (Group group in Groups)
            {
                if (group.ParentId == parentId)
                {
                    result.Add(group);
                    CollectDescendants(group.Id, result, depth + 1);
                }
            }
        }

        /// <summary>Уровень вложенности группы: 1 — верхний уровень. 0, если группы нет.</summary>
        public int DepthOf(string id)
        {
            int depth = 0;
            Group group = FindGroup(id);
            while (group != null && depth <= Groups.Count)
            {
                depth++;
                group = FindGroup(group.ParentId);
            }
            return depth;
        }

        /// <summary>Число уровней в ветке, начиная с самой группы: 1 — подгрупп нет.</summary>
        private int HeightOf(string id, int guard)
        {
            int tallest = 0;
            if (guard <= Groups.Count)
            {
                foreach (Group child in ChildrenOf(id))
                {
                    tallest = Math.Max(tallest, HeightOf(child.Id, guard + 1));
                }
            }
            return tallest + 1;
        }

        /// <summary>
        /// Все группы в порядке обхода дерева: группа, сразу за ней её подгруппы.
        /// Соседние группы упорядочиваются по названию функцией compareNames.
        /// </summary>
        public List<Group> TreeOrder(Comparison<string> compareNames)
        {
            var result = new List<Group>();
            AppendBranch(null, compareNames, result, 0);
            return result;
        }

        private void AppendBranch(string parentId, Comparison<string> compareNames, List<Group> result, int depth)
        {
            if (depth > Groups.Count) return;
            List<Group> children = ChildrenOf(parentId);
            children.Sort(delegate(Group a, Group b) { return compareNames(a.Name, b.Name); });
            foreach (Group child in children)
            {
                result.Add(child);
                AppendBranch(child.Id, compareNames, result, depth + 1);
            }
        }

        /// <summary>
        /// Проверяет название группы: оно не должно повторяться среди соседних групп
        /// (в той же родительской). Возвращает текст ошибки или null, если всё в порядке.
        /// </summary>
        public string ValidateGroupName(string name, string parentId, string exceptGroupId)
        {
            string trimmed = (name ?? "").Trim();
            if (trimmed.Length == 0)
            {
                return L.T("Введите название группы.", "Enter a group name.");
            }
            if (trimmed.Length > MaxGroupNameLength)
            {
                return L.F("Название группы не должно быть длиннее {0} символов.", "A group name cannot be longer than {0} characters.", MaxGroupNameLength);
            }

            string parent = NormalizeId(parentId);
            foreach (Group group in Groups)
            {
                if (group.Id != exceptGroupId && group.ParentId == parent &&
                    string.Equals(group.Name, trimmed, StringComparison.OrdinalIgnoreCase))
                {
                    Group owner = FindGroup(parent);
                    return owner == null
                        ? L.F("Группа «{0}» уже существует.", "The group “{0}” already exists.", group.Name)
                        : L.F("В группе «{0}» уже есть подгруппа «{1}».", "The group “{0}” already has a subgroup “{1}”.", owner.Name, group.Name);
                }
            }
            return null;
        }

        /// <summary>
        /// Проверяет, можно ли поместить группу в указанную родительскую (null — на верхний уровень).
        /// groupId — перемещаемая группа или null для новой. Возвращает текст ошибки или null.
        /// </summary>
        public string ValidateGroupParent(string groupId, string parentId)
        {
            string parent = NormalizeId(parentId);
            if (parent == null) return null;
            if (FindGroup(parent) == null) return L.T("Группа не найдена.", "Group not found.");

            int levels = 1;
            if (!string.IsNullOrEmpty(groupId))
            {
                if (parent == groupId) return L.T("Группу нельзя вложить в саму себя.", "A group cannot be placed inside itself.");
                foreach (Group descendant in DescendantsOf(groupId))
                {
                    if (descendant.Id == parent) return L.T("Группу нельзя вложить в её собственную подгруппу.", "A group cannot be placed inside its own subgroup.");
                }
                levels = HeightOf(groupId, 0);
            }
            if (DepthOf(parent) + levels > MaxGroupDepth)
            {
                return L.F("Слишком глубокая вложенность: допускается не больше {0} уровней.", "Nesting is too deep: no more than {0} levels are allowed.", MaxGroupDepth);
            }
            return null;
        }

        /// <summary>Создаёт группу верхнего уровня.</summary>
        public Group AddGroup(string name)
        {
            return AddGroup(name, null);
        }

        /// <summary>Создаёт группу внутри родительской (null — на верхнем уровне).</summary>
        public Group AddGroup(string name, string parentId)
        {
            string error = ValidateGroupParent(null, parentId) ?? ValidateGroupName(name, parentId, null);
            if (error != null) throw new ValidationException(error);

            var group = new Group();
            group.Id = NewId();
            group.Name = name.Trim();
            group.ParentId = NormalizeId(parentId);
            group.Changed = Timestamp();
            Groups.Add(group);
            return group;
        }

        /// <summary>
        /// Меняет название группы и её место в дереве. Подгруппы и записи переезжают вместе с ней.
        /// Возвращает true, если что-нибудь действительно изменилось.
        /// </summary>
        public bool UpdateGroup(string id, string name, string parentId)
        {
            Group group = RequireGroup(id);
            string parent = NormalizeId(parentId);
            string error = ValidateGroupParent(id, parent) ?? ValidateGroupName(name, parent, id);
            if (error != null) throw new ValidationException(error);

            string newName = name.Trim();
            bool changed = group.Name != newName || group.ParentId != parent;
            group.Name = newName;
            group.ParentId = parent;
            if (changed) group.Changed = Timestamp();
            return changed;
        }

        public void RenameGroup(string id, string name)
        {
            UpdateGroup(id, name, RequireGroup(id).ParentId);
        }

        /// <summary>Переносит группу в другую родительскую (null — на верхний уровень).</summary>
        public bool MoveGroup(string id, string parentId)
        {
            return UpdateGroup(id, RequireGroup(id).Name, parentId);
        }

        /// <summary>Число записей в группе и во всех её подгруппах.</summary>
        public int CountInBranch(string id)
        {
            var branch = new HashSet<string>();
            branch.Add(id);
            foreach (Group descendant in DescendantsOf(id)) branch.Add(descendant.Id);

            int count = 0;
            foreach (Entry entry in Entries)
            {
                if (!entry.IsDeleted && entry.GroupId != null && branch.Contains(entry.GroupId)) count++;
            }
            return count;
        }

        /// <summary>
        /// Удаляет группу вместе с её подгруппами. Записи не удаляются: все записи из удалённых
        /// групп переходят на уровень выше — в родительскую группу, а если её нет, остаются без группы.
        /// Возвращает число таких записей.
        /// </summary>
        public int DeleteGroup(string id)
        {
            Group group = RequireGroup(id);
            var removed = new HashSet<string>();
            removed.Add(group.Id);
            foreach (Group descendant in DescendantsOf(group.Id)) removed.Add(descendant.Id);

            string destination = group.ParentId;
            string now = Timestamp();
            int released = 0;
            foreach (Entry entry in Entries)
            {
                if (entry.GroupId != null && removed.Contains(entry.GroupId))
                {
                    // Записи из корзины тоже переезжают (иначе после восстановления им некуда вернуться),
                    // но в счёт не идут: пользователь их сейчас не видит.
                    entry.GroupId = destination;
                    entry.Changed = now;
                    if (!entry.IsDeleted) released++;
                }
            }
            foreach (string removedId in removed) AddTombstone(removedId, now);
            Groups.RemoveAll(delegate(Group candidate) { return removed.Contains(candidate.Id); });
            return released;
        }

        /// <summary>Число записей в каждой группе и отдельно — без группы.</summary>
        public Dictionary<string, int> CountByGroup(out int ungrouped)
        {
            var counts = new Dictionary<string, int>();
            foreach (Group group in Groups)
            {
                counts[group.Id] = 0;
            }
            ungrouped = 0;
            foreach (Entry entry in Entries)
            {
                if (entry.IsDeleted) continue;
                int current;
                if (!string.IsNullOrEmpty(entry.GroupId) && counts.TryGetValue(entry.GroupId, out current))
                {
                    counts[entry.GroupId] = current + 1;
                }
                else
                {
                    ungrouped++;
                }
            }
            return counts;
        }

        // ---------- Записи ----------

        public Entry FindEntry(string id)
        {
            if (string.IsNullOrEmpty(id)) return null;
            foreach (Entry entry in Entries)
            {
                if (entry.Id == id) return entry;
            }
            return null;
        }

        /// <summary>Число записей вне корзины.</summary>
        public int LiveCount
        {
            get
            {
                int count = 0;
                foreach (Entry entry in Entries)
                {
                    if (!entry.IsDeleted) count++;
                }
                return count;
            }
        }

        /// <summary>Число записей в корзине.</summary>
        public int TrashCount
        {
            get { return Entries.Count - LiveCount; }
        }

        /// <summary>Проверяет поля записи. Возвращает текст ошибки или null.</summary>
        public static string ValidateEntry(string login, string password, string description)
        {
            var fields = new EntryFields();
            fields.Login = login;
            fields.Password = password;
            fields.Description = description;
            return ValidateEntry(fields);
        }

        /// <summary>Проверяет поля записи. Возвращает текст ошибки или null.</summary>
        public static string ValidateEntry(EntryFields fields)
        {
            if (fields == null) throw new ArgumentNullException("fields");

            if (IsBlank(fields.Login) && IsBlank(fields.Description))
            {
                return L.T("Заполните описание или логин.", "Fill in the description or the username.");
            }
            if ((fields.Login ?? "").Length > MaxLoginLength)
            {
                return L.F("Логин не должен быть длиннее {0} символов.", "The username cannot be longer than {0} characters.", MaxLoginLength);
            }
            if ((fields.Password ?? "").Length > MaxPasswordLength)
            {
                return L.F("Пароль не должен быть длиннее {0} символов.", "The password cannot be longer than {0} characters.", MaxPasswordLength);
            }
            if ((fields.Description ?? "").Length > MaxDescriptionLength)
            {
                return L.F("Описание не должно быть длиннее {0} символов.", "The description cannot be longer than {0} characters.", MaxDescriptionLength);
            }
            if ((fields.Url ?? "").Trim().Length > MaxUrlLength)
            {
                return L.F("Адрес сайта не должен быть длиннее {0} символов.", "The website address cannot be longer than {0} characters.", MaxUrlLength);
            }

            string totp = (fields.Totp ?? "").Trim();
            if (totp.Length > MaxTotpLength || (totp.Length > 0 && Totp.Parse(totp) == null))
            {
                return L.T("Ключ одноразовых кодов не распознан. Нужен ключ из букв A–Z и цифр 2–7 или ссылка otpauth://.",
                           "The one-time code key is not recognised. Enter a key made of letters A–Z and digits 2–7, or an otpauth:// link.");
            }
            return null;
        }

        public Entry AddEntry(string groupId, string login, string password, string description)
        {
            var fields = new EntryFields();
            fields.GroupId = groupId;
            fields.Login = login;
            fields.Password = password;
            fields.Description = description;
            return AddEntry(fields);
        }

        public Entry AddEntry(EntryFields fields)
        {
            string error = ValidateEntry(fields);
            if (error != null) throw new ValidationException(error);

            string now = Timestamp();
            var entry = new Entry();
            entry.Id = NewId();
            entry.GroupId = ResolveGroupId(fields.GroupId);
            entry.Login = CleanLine(fields.Login);
            entry.Password = fields.Password ?? "";
            entry.Description = CleanText(fields.Description);
            entry.Url = CleanOptional(fields.Url);
            entry.Totp = CleanOptional(fields.Totp);
            entry.Created = now;
            entry.Modified = now;
            entry.Changed = now;
            Entries.Add(entry);
            return entry;
        }

        /// <summary>
        /// Обновляет группу, логин, пароль и описание записи; адрес сайта и ключ одноразовых кодов
        /// остаются прежними. Возвращает true, если что-нибудь действительно изменилось.
        /// </summary>
        public bool UpdateEntry(string id, string groupId, string login, string password, string description)
        {
            Entry entry = RequireEntry(id);
            var fields = new EntryFields();
            fields.GroupId = groupId;
            fields.Login = login;
            fields.Password = password;
            fields.Description = description;
            fields.Url = entry.Url;
            fields.Totp = entry.Totp;
            return UpdateEntry(id, fields);
        }

        /// <summary>
        /// Обновляет запись. Прежний пароль при замене уходит в историю записи.
        /// Возвращает true, если что-нибудь действительно изменилось.
        /// </summary>
        public bool UpdateEntry(string id, EntryFields fields)
        {
            Entry entry = RequireEntry(id);
            string error = ValidateEntry(fields);
            if (error != null) throw new ValidationException(error);

            string newGroupId = ResolveGroupId(fields.GroupId);
            string newLogin = CleanLine(fields.Login);
            string newPassword = fields.Password ?? "";
            string newDescription = CleanText(fields.Description);
            string newUrl = CleanOptional(fields.Url);
            string newTotp = CleanOptional(fields.Totp);

            bool contentChanged = entry.Login != newLogin || entry.Password != newPassword || entry.Description != newDescription ||
                                  entry.Url != newUrl || entry.Totp != newTotp;
            bool groupChanged = entry.GroupId != newGroupId;
            if (!contentChanged && !groupChanged) return false;

            string now = Timestamp();
            entry.GroupId = newGroupId;
            if (contentChanged)
            {
                if (entry.Password != newPassword) RememberPassword(entry, entry.Password, now);
                entry.Login = newLogin;
                entry.Password = newPassword;
                entry.Description = newDescription;
                entry.Url = newUrl;
                entry.Totp = newTotp;
                entry.Modified = now;
            }
            entry.Changed = now;
            return true;
        }

        /// <summary>Прежний пароль уходит в историю записи. Пустой пароль не запоминается.</summary>
        private static void RememberPassword(Entry entry, string password, string when)
        {
            if (string.IsNullOrEmpty(password)) return;
            if (entry.History == null) entry.History = new List<PasswordRecord>();

            var record = new PasswordRecord();
            record.Password = password;
            record.Replaced = when;
            entry.History.Insert(0, record);
            if (entry.History.Count > MaxHistory)
            {
                entry.History.RemoveRange(MaxHistory, entry.History.Count - MaxHistory);
            }
        }

        /// <summary>Стирает историю паролей записи. Возвращает true, если было что стирать.</summary>
        public bool ClearHistory(string id)
        {
            Entry entry = RequireEntry(id);
            if (entry.History == null || entry.History.Count == 0) return false;
            entry.History = null;
            entry.Changed = Timestamp();
            return true;
        }

        /// <summary>Перемещает записи в корзину. Возвращает число перемещённых.</summary>
        public int TrashEntries(IEnumerable<string> ids)
        {
            var set = new HashSet<string>(ids);
            string now = Timestamp();
            int count = 0;
            foreach (Entry entry in Entries)
            {
                if (set.Contains(entry.Id) && !entry.IsDeleted)
                {
                    entry.Deleted = now;
                    entry.Changed = now;
                    count++;
                }
            }
            return count;
        }

        /// <summary>Возвращает записи из корзины на прежнее место. Возвращает число восстановленных.</summary>
        public int RestoreEntries(IEnumerable<string> ids)
        {
            var set = new HashSet<string>(ids);
            string now = Timestamp();
            int count = 0;
            foreach (Entry entry in Entries)
            {
                if (set.Contains(entry.Id) && entry.IsDeleted)
                {
                    entry.Deleted = null;
                    entry.Changed = now;
                    count++;
                }
            }
            return count;
        }

        /// <summary>Удаляет записи окончательно, минуя корзину. Возвращает число удалённых.</summary>
        public int DeleteEntries(IEnumerable<string> ids)
        {
            var set = new HashSet<string>(ids);
            string now = Timestamp();
            int removed = 0;
            for (int i = Entries.Count - 1; i >= 0; i--)
            {
                if (!set.Contains(Entries[i].Id)) continue;
                AddTombstone(Entries[i].Id, now);
                Entries.RemoveAt(i);
                removed++;
            }
            return removed;
        }

        /// <summary>Окончательно удаляет всё, что лежит в корзине. Возвращает число удалённых записей.</summary>
        public int EmptyTrash()
        {
            var ids = new List<string>();
            foreach (Entry entry in Entries)
            {
                if (entry.IsDeleted) ids.Add(entry.Id);
            }
            return DeleteEntries(ids);
        }

        /// <summary>
        /// Окончательно удаляет записи, пролежавшие в корзине не меньше указанного числа дней.
        /// Возвращает число удалённых.
        /// </summary>
        public int PurgeTrash(int days, DateTime utcNow)
        {
            var ids = new List<string>();
            foreach (Entry entry in Entries)
            {
                DateTime deleted;
                if (entry.IsDeleted && TryParseUtc(entry.Deleted, out deleted) && (utcNow - deleted).TotalDays >= days)
                {
                    ids.Add(entry.Id);
                }
            }
            return DeleteEntries(ids);
        }

        /// <summary>
        /// Перемещает записи в группу (null — «без группы»).
        /// Возвращает число записей, у которых группа действительно изменилась.
        /// </summary>
        public int MoveEntries(IEnumerable<string> ids, string groupId)
        {
            string target = ResolveGroupId(groupId);
            var set = new HashSet<string>(ids);
            string now = Timestamp();
            int moved = 0;
            foreach (Entry entry in Entries)
            {
                if (set.Contains(entry.Id) && !entry.IsDeleted && entry.GroupId != target)
                {
                    entry.GroupId = target;
                    entry.Changed = now;
                    moved++;
                }
            }
            return moved;
        }

        private void AddTombstone(string id, string when)
        {
            if (Removed == null) Removed = new List<Tombstone>();
            foreach (Tombstone existing in Removed)
            {
                if (existing.Id == id)
                {
                    existing.When = when;
                    return;
                }
            }
            var tombstone = new Tombstone();
            tombstone.Id = id;
            tombstone.When = when;
            Removed.Add(tombstone);
        }

        // ---------- Настройки ----------

        /// <summary>Действующие настройки: сохранённые в хранилище или значения по умолчанию.</summary>
        public VaultSettings EffectiveSettings
        {
            get { return Settings != null ? Settings.Clone() : VaultSettings.Defaults(); }
        }

        /// <summary>Сохраняет настройки. Возвращает true, если они изменились.</summary>
        public bool UpdateSettings(VaultSettings settings)
        {
            if (settings == null) throw new ArgumentNullException("settings");
            VaultSettings updated = settings.Clone();
            updated.Normalize();
            if (updated.SameAs(EffectiveSettings)) return false;
            updated.Changed = Timestamp();
            Settings = updated;
            return true;
        }

        /// <summary>Пути ко всем группам: идентификатор → «Работа / Проекты».</summary>
        public Dictionary<string, string> GroupPaths()
        {
            var paths = new Dictionary<string, string>();
            foreach (Group group in Groups)
            {
                paths[group.Id] = GroupPath(group.Id);
            }
            return paths;
        }

        /// <summary>
        /// Записи, подходящие под фильтр по группе и строку поиска. Фильтр по группе показывает
        /// записи, лежащие непосредственно в ней (без подгрупп). Поиск идёт по описанию, логину,
        /// адресу сайта и пути к группе, так что по названию группы находятся и записи её подгрупп;
        /// несколько слов должны найтись все. По паролям поиска нет.
        /// </summary>
        public List<Entry> Query(GroupFilter filter, string search)
        {
            string[] terms = (search ?? "").Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);
            Dictionary<string, string> groupPaths = terms.Length > 0 ? GroupPaths() : null;

            var result = new List<Entry>();
            foreach (Entry entry in Entries)
            {
                if (!filter.Matches(entry)) continue;
                if (terms.Length > 0)
                {
                    string groupPath = null;
                    if (!string.IsNullOrEmpty(entry.GroupId))
                    {
                        groupPaths.TryGetValue(entry.GroupId, out groupPath);
                    }
                    if (!MatchesAll(terms, entry.Description, entry.Login, entry.Url, groupPath)) continue;
                }
                result.Add(entry);
            }
            return result;
        }

        private static bool MatchesAll(string[] terms, string description, string login, string url, string groupName)
        {
            foreach (string term in terms)
            {
                if (!Contains(description, term) && !Contains(login, term) && !Contains(url, term) && !Contains(groupName, term))
                {
                    return false;
                }
            }
            return true;
        }

        private static bool Contains(string text, string term)
        {
            return !string.IsNullOrEmpty(text) && text.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        // ---------- JSON ----------

        public byte[] ToJson()
        {
            Version = RequiredVersion();
            var serializer = new DataContractJsonSerializer(typeof(VaultData));
            using (var stream = new MemoryStream())
            {
                serializer.WriteObject(stream, this);
                byte[] result = stream.ToArray();
                // Во внутреннем буфере потока остаётся копия открытых данных — затираем.
                byte[] buffer = stream.GetBuffer();
                Array.Clear(buffer, 0, buffer.Length);
                return result;
            }
        }

        public static VaultData FromJson(byte[] json)
        {
            VaultData data = null;
            Exception failure = null;
            try
            {
                var serializer = new DataContractJsonSerializer(typeof(VaultData));
                using (var stream = new MemoryStream(json, false))
                {
                    data = serializer.ReadObject(stream) as VaultData;
                }
            }
            catch (SerializationException ex) { failure = ex; }
            catch (System.Xml.XmlException ex) { failure = ex; }
            catch (FormatException ex) { failure = ex; }
            catch (ArgumentException ex) { failure = ex; }
            catch (InvalidOperationException ex) { failure = ex; }

            if (failure != null || data == null)
            {
                throw new VaultException(VaultError.BadFormat,
                    L.T("Содержимое хранилища повреждено и не может быть прочитано.", "The vault contents are damaged and cannot be read."), failure);
            }
            if (data.Version > CurrentVersion)
            {
                throw new VaultException(VaultError.UnsupportedVersion,
                    L.T("Хранилище создано более новой версией KeyBox. Обновите программу.", "The vault was created by a newer version of KeyBox. Update the program."));
            }
            data.Normalize();
            return data;
        }

        /// <summary>Наименьшая версия структуры, которой достаточно для этих данных.</summary>
        private int RequiredVersion()
        {
            // Служебные отметки времени и следы удалённого версию не повышают: прежние версии
            // программы их просто не заметят, и данные от этого не пострадают.
            if (Settings != null) return 3;
            foreach (Entry entry in Entries)
            {
                if (entry.Url != null || entry.Totp != null || entry.IsDeleted ||
                    (entry.History != null && entry.History.Count > 0))
                {
                    return 3;
                }
            }
            foreach (Group group in Groups)
            {
                if (group.ParentId != null) return 2;
            }
            return 1;
        }

        /// <summary>Приводит прочитанные данные к согласованному виду.</summary>
        private void Normalize()
        {
            if (Groups == null) Groups = new List<Group>();
            if (Entries == null) Entries = new List<Entry>();
            Groups.RemoveAll(delegate(Group group) { return group == null; });
            Entries.RemoveAll(delegate(Entry entry) { return entry == null; });

            var groupIds = new HashSet<string>();
            foreach (Group group in Groups)
            {
                if (string.IsNullOrEmpty(group.Id) || groupIds.Contains(group.Id))
                {
                    group.Id = NewId();
                }
                groupIds.Add(group.Id);
                group.Name = (group.Name ?? "").Trim();
                if (group.Name.Length == 0) group.Name = L.T("Группа", "Group");
            }

            // Ссылки на родительские группы: несуществующая или на саму себя — группа уходит на верхний уровень.
            foreach (Group group in Groups)
            {
                if (string.IsNullOrEmpty(group.ParentId) || group.ParentId == group.Id || !groupIds.Contains(group.ParentId))
                {
                    group.ParentId = null;
                }
            }

            // Кольца (А в Б, Б в А) разрываются: иначе такие группы не попали бы в дерево вовсе.
            foreach (Group group in Groups)
            {
                var visited = new HashSet<string>();
                visited.Add(group.Id);
                Group ancestor = FindGroup(group.ParentId);
                while (ancestor != null)
                {
                    if (!visited.Add(ancestor.Id))
                    {
                        group.ParentId = null;
                        break;
                    }
                    ancestor = FindGroup(ancestor.ParentId);
                }
            }

            var entryIds = new HashSet<string>();
            foreach (Entry entry in Entries)
            {
                if (string.IsNullOrEmpty(entry.Id) || entryIds.Contains(entry.Id))
                {
                    entry.Id = NewId();
                }
                entryIds.Add(entry.Id);
                if (string.IsNullOrEmpty(entry.GroupId) || !groupIds.Contains(entry.GroupId))
                {
                    entry.GroupId = null;
                }
                entry.Login = entry.Login ?? "";
                entry.Password = entry.Password ?? "";
                entry.Description = entry.Description ?? "";
                entry.Url = CleanOptional(entry.Url);
                entry.Totp = CleanOptional(entry.Totp);
                if (string.IsNullOrEmpty(entry.Deleted)) entry.Deleted = null;
                if (entry.History != null)
                {
                    entry.History.RemoveAll(delegate(PasswordRecord record) { return record == null || string.IsNullOrEmpty(record.Password); });
                    if (entry.History.Count == 0) entry.History = null;
                }
            }

            if (Settings != null) Settings.Normalize();

            if (Removed != null)
            {
                // След не нужен, если такой записи или группы нет в следах дважды, и вреден, если она на самом деле есть.
                var seen = new HashSet<string>();
                Removed.RemoveAll(delegate(Tombstone tombstone)
                {
                    return tombstone == null || string.IsNullOrEmpty(tombstone.Id) ||
                           entryIds.Contains(tombstone.Id) || groupIds.Contains(tombstone.Id) || !seen.Add(tombstone.Id);
                });
                if (Removed.Count == 0) Removed = null;
            }

            Version = RequiredVersion();
        }

        // ---------- Вспомогательное ----------

        private Group RequireGroup(string id)
        {
            Group group = FindGroup(id);
            if (group == null) throw new ValidationException(L.T("Группа не найдена.", "Group not found."));
            return group;
        }

        private Entry RequireEntry(string id)
        {
            Entry entry = FindEntry(id);
            if (entry == null) throw new ValidationException(L.T("Запись не найдена.", "Entry not found."));
            return entry;
        }

        private string ResolveGroupId(string groupId)
        {
            if (string.IsNullOrEmpty(groupId)) return null;
            return RequireGroup(groupId).Id;
        }

        /// <summary>Пустой идентификатор и null означают одно и то же — «нет группы».</summary>
        private static string NormalizeId(string id)
        {
            return string.IsNullOrEmpty(id) ? null : id;
        }

        private static bool IsBlank(string value)
        {
            return string.IsNullOrWhiteSpace(value);
        }

        private static string CleanLine(string value)
        {
            return (value ?? "").Trim();
        }

        private static string CleanText(string value)
        {
            return (value ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Trim();
        }

        /// <summary>Необязательное поле: пустое значение хранится как null и в файл не пишется.</summary>
        private static string CleanOptional(string value)
        {
            string trimmed = (value ?? "").Trim();
            return trimmed.Length == 0 ? null : trimmed;
        }

        private static string NewId()
        {
            return Guid.NewGuid().ToString("N");
        }

        private static string Timestamp()
        {
            return DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }

        /// <summary>Разбирает метку времени из хранилища. Возвращает false, если её нет.</summary>
        public static bool TryParseTimestamp(string value, out DateTime local)
        {
            DateTime parsed;
            if (!string.IsNullOrEmpty(value) &&
                DateTime.TryParse(value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed))
            {
                local = parsed.ToLocalTime();
                return true;
            }
            local = DateTime.MinValue;
            return false;
        }

        /// <summary>Разбирает метку времени из хранилища как время UTC. Возвращает false, если её нет.</summary>
        public static bool TryParseUtc(string value, out DateTime utc)
        {
            if (!string.IsNullOrEmpty(value) &&
                DateTime.TryParse(value, CultureInfo.InvariantCulture,
                    DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out utc))
            {
                return true;
            }
            utc = DateTime.MinValue;
            return false;
        }
    }
}
