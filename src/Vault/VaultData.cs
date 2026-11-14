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

    /// <summary>Группа паролей.</summary>
    [DataContract]
    internal sealed class Group
    {
        [DataMember(Name = "id", Order = 0)]
        public string Id { get; set; }

        [DataMember(Name = "name", Order = 1)]
        public string Name { get; set; }
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
        public const int CurrentVersion = 1;
        public const int MaxGroupNameLength = 100;
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
            data.Version = CurrentVersion;
            data.Groups = new List<Group>();
            data.Entries = new List<Entry>();
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

        /// <summary>Проверяет название группы. Возвращает текст ошибки или null, если всё в порядке.</summary>
        public string ValidateGroupName(string name, string exceptGroupId)
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
            foreach (Group group in Groups)
            {
                if (group.Id != exceptGroupId && string.Equals(group.Name, trimmed, StringComparison.OrdinalIgnoreCase))
                {
                    return string.Format("Группа «{0}» уже существует.", group.Name);
                }
            }
            return null;
        }

        public Group AddGroup(string name)
        {
            string error = ValidateGroupName(name, null);
            if (error != null) throw new ValidationException(error);

            var group = new Group();
            group.Id = NewId();
            group.Name = name.Trim();
            Groups.Add(group);
            return group;
        }

        public void RenameGroup(string id, string name)
        {
            Group group = RequireGroup(id);
            string error = ValidateGroupName(name, id);
            if (error != null) throw new ValidationException(error);
            group.Name = name.Trim();
        }

        /// <summary>
        /// Удаляет группу. Записи не удаляются — они остаются без группы.
        /// Возвращает число таких записей.
        /// </summary>
        public int DeleteGroup(string id)
        {
            Group group = RequireGroup(id);
            int released = 0;
            foreach (Entry entry in Entries)
            {
                if (entry.GroupId == id)
                {
                    entry.GroupId = null;
                    released++;
                }
            }
            Groups.Remove(group);
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

        /// <summary>
        /// Записи, подходящие под фильтр по группе и строку поиска. Поиск идёт по описанию,
        /// логину и названию группы; несколько слов должны найтись все. По паролям поиска нет.
        /// </summary>
        public List<Entry> Query(GroupFilter filter, string search)
        {
            string[] terms = (search ?? "").Split(Whitespace, StringSplitOptions.RemoveEmptyEntries);

            Dictionary<string, string> groupNames = null;
            if (terms.Length > 0)
            {
                groupNames = new Dictionary<string, string>();
                foreach (Group group in Groups)
                {
                    groupNames[group.Id] = group.Name;
                }
            }

            var result = new List<Entry>();
            foreach (Entry entry in Entries)
            {
                if (!filter.Matches(entry)) continue;
                if (terms.Length > 0)
                {
                    string groupName = null;
                    if (!string.IsNullOrEmpty(entry.GroupId))
                    {
                        groupNames.TryGetValue(entry.GroupId, out groupName);
                    }
                    if (!MatchesAll(terms, entry.Description, entry.Login, groupName)) continue;
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

        /// <summary>Приводит прочитанные данные к согласованному виду.</summary>
        private void Normalize()
        {
            Version = CurrentVersion;
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
