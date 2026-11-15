using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

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
    }

    internal enum FilterKind
    {
        All,
        Ungrouped,
        Group
    }

    /// <summary>Какую часть записей показывать: все, без группы или одну группу.</summary>
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
        /// Версия структуры данных. 1 — группы одним списком, 2 — группы могут быть вложенными.
        /// Файл помечается версией 2, только если вложенность действительно используется:
        /// так хранилище без вложенных групп по-прежнему открывается программой версии 1.0,
        /// а с вложенными она честно откажется открывать, вместо того чтобы потерять структуру.
        /// </summary>
        public const int CurrentVersion = 2;

        public const int MaxGroupNameLength = 100;

        /// <summary>Наибольшая глубина вложенности групп (1 — только верхний уровень).</summary>
        public const int MaxGroupDepth = 8;

        /// <summary>Разделитель в пути к группе: «Работа / Проекты».</summary>
        public const string PathSeparator = " / ";

        public const int MaxLoginLength = 1000;
        public const int MaxPasswordLength = 1000;
        public const int MaxDescriptionLength = 10000;

        private static readonly char[] Whitespace = { ' ', '\t', '\r', '\n' };

        [DataMember(Name = "version", Order = 0)]
        public int Version { get; set; }

        [DataMember(Name = "groups", Order = 1)]
        public List<Group> Groups { get; set; }

        [DataMember(Name = "entries", Order = 2)]
        public List<Entry> Entries { get; set; }

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
                return "Введите название группы.";
            }
            if (trimmed.Length > MaxGroupNameLength)
            {
                return string.Format("Название группы не должно быть длиннее {0} символов.", MaxGroupNameLength);
            }

            string parent = NormalizeId(parentId);
            foreach (Group group in Groups)
            {
                if (group.Id != exceptGroupId && group.ParentId == parent &&
                    string.Equals(group.Name, trimmed, StringComparison.OrdinalIgnoreCase))
                {
                    Group owner = FindGroup(parent);
                    return owner == null
                        ? string.Format("Группа «{0}» уже существует.", group.Name)
                        : string.Format("В группе «{0}» уже есть подгруппа «{1}».", owner.Name, group.Name);
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
            if (FindGroup(parent) == null) return "Группа не найдена.";

            int levels = 1;
            if (!string.IsNullOrEmpty(groupId))
            {
                if (parent == groupId) return "Группу нельзя вложить в саму себя.";
                foreach (Group descendant in DescendantsOf(groupId))
                {
                    if (descendant.Id == parent) return "Группу нельзя вложить в её собственную подгруппу.";
                }
                levels = HeightOf(groupId, 0);
            }
            if (DepthOf(parent) + levels > MaxGroupDepth)
            {
                return string.Format("Слишком глубокая вложенность: допускается не больше {0} уровней.", MaxGroupDepth);
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
                if (entry.GroupId != null && branch.Contains(entry.GroupId)) count++;
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
            int released = 0;
            foreach (Entry entry in Entries)
            {
                if (entry.GroupId != null && removed.Contains(entry.GroupId))
                {
                    entry.GroupId = destination;
                    released++;
                }
            }
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

        /// <summary>Проверяет поля записи. Возвращает текст ошибки или null.</summary>
        public static string ValidateEntry(string login, string password, string description)
        {
            if (IsBlank(login) && IsBlank(description))
            {
                return "Заполните описание или логин.";
            }
            if ((login ?? "").Length > MaxLoginLength)
            {
                return string.Format("Логин не должен быть длиннее {0} символов.", MaxLoginLength);
            }
            if ((password ?? "").Length > MaxPasswordLength)
            {
                return string.Format("Пароль не должен быть длиннее {0} символов.", MaxPasswordLength);
            }
            if ((description ?? "").Length > MaxDescriptionLength)
            {
                return string.Format("Описание не должно быть длиннее {0} символов.", MaxDescriptionLength);
            }
            return null;
        }

        public Entry AddEntry(string groupId, string login, string password, string description)
        {
            string error = ValidateEntry(login, password, description);
            if (error != null) throw new ValidationException(error);

            string now = Timestamp();
            var entry = new Entry();
            entry.Id = NewId();
            entry.GroupId = ResolveGroupId(groupId);
            entry.Login = CleanLine(login);
            entry.Password = password ?? "";
            entry.Description = CleanText(description);
            entry.Created = now;
            entry.Modified = now;
            Entries.Add(entry);
            return entry;
        }

        /// <summary>Обновляет запись. Возвращает true, если что-нибудь действительно изменилось.</summary>
        public bool UpdateEntry(string id, string groupId, string login, string password, string description)
        {
            Entry entry = RequireEntry(id);
            string error = ValidateEntry(login, password, description);
            if (error != null) throw new ValidationException(error);

            string newGroupId = ResolveGroupId(groupId);
            string newLogin = CleanLine(login);
            string newPassword = password ?? "";
            string newDescription = CleanText(description);

            bool contentChanged = entry.Login != newLogin || entry.Password != newPassword || entry.Description != newDescription;
            bool groupChanged = entry.GroupId != newGroupId;

            entry.GroupId = newGroupId;
            if (contentChanged)
            {
                entry.Login = newLogin;
                entry.Password = newPassword;
                entry.Description = newDescription;
                entry.Modified = Timestamp();
            }
            return contentChanged || groupChanged;
        }

        /// <summary>Удаляет записи. Возвращает число удалённых.</summary>
        public int DeleteEntries(IEnumerable<string> ids)
        {
            var set = new HashSet<string>(ids);
            return Entries.RemoveAll(delegate(Entry entry) { return set.Contains(entry.Id); });
        }

        /// <summary>
        /// Перемещает записи в группу (null — «без группы»).
        /// Возвращает число записей, у которых группа действительно изменилась.
        /// </summary>
        public int MoveEntries(IEnumerable<string> ids, string groupId)
        {
            string target = ResolveGroupId(groupId);
            var set = new HashSet<string>(ids);
            int moved = 0;
            foreach (Entry entry in Entries)
            {
                if (set.Contains(entry.Id) && entry.GroupId != target)
                {
                    entry.GroupId = target;
                    moved++;
                }
            }
            return moved;
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
        /// записи, лежащие непосредственно в ней (без подгрупп). Поиск идёт по описанию, логину
        /// и пути к группе, так что по названию группы находятся и записи её подгрупп;
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
                    if (!MatchesAll(terms, entry.Description, entry.Login, groupPath)) continue;
                }
                result.Add(entry);
            }
            return result;
        }

        private static bool MatchesAll(string[] terms, string description, string login, string groupName)
        {
            foreach (string term in terms)
            {
                if (!Contains(description, term) && !Contains(login, term) && !Contains(groupName, term))
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
                    "Содержимое хранилища повреждено и не может быть прочитано.", failure);
            }
            if (data.Version > CurrentVersion)
            {
                throw new VaultException(VaultError.UnsupportedVersion,
                    "Хранилище создано более новой версией KeyBox. Обновите программу.");
            }
            data.Normalize();
            return data;
        }

        /// <summary>Наименьшая версия структуры, которой достаточно для этих данных.</summary>
        private int RequiredVersion()
        {
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
                if (group.Name.Length == 0) group.Name = "Группа";
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
            }

            Version = RequiredVersion();
        }

        // ---------- Вспомогательное ----------

        private Group RequireGroup(string id)
        {
            Group group = FindGroup(id);
            if (group == null) throw new ValidationException("Группа не найдена.");
            return group;
        }

        private Entry RequireEntry(string id)
        {
            Entry entry = FindEntry(id);
            if (entry == null) throw new ValidationException("Запись не найдена.");
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
    }
}
