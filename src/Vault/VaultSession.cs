using System;
using System.IO;
using System.Security;
using System.Security.Cryptography;
using System.Threading;
using KeyBox.Crypto;

namespace KeyBox.Vault
{
    /// <summary>
    /// Открытое хранилище: расшифрованные данные и ключ, которым они шифруются при сохранении.
    /// Мастер-пароль в памяти не хранится — только полученный из него ключ.
    /// </summary>
    internal sealed class VaultSession : IDisposable
    {
        private readonly object sync = new object();
        private byte[] key;
        private KdfParameters kdf;

        // SHA-512 ключевого файла (если он используется). Нужен, чтобы проверить мастер-пароль
        // при его смене, не спрашивая файл заново. Затирается вместе с ключом.
        private byte[] keyFileHash;
        private bool disposed;

        // Каким эта сессия видела файл в последний раз (прочитала или записала сама): хеш
        // содержимого, размер и время изменения. По ним видно, что файл изменил кто-то ещё —
        // другая копия программы на другом компьютере, через облачную папку.
        private byte[] fileHash;
        private long seenLength = -1;
        private DateTime seenTime;

        // Что влилось из файла и ещё не показано пользователю.
        private MergeResult merged;

        // Сколько раз подряд файл дописан при проверке (Reload) без участия пользователя.
        private const int MaxUnattendedWrites = 3;
        private int unattendedWrites;

        // Сколько раз и с какой паузой перечитывать занятый файл перед записью.
        private const int BusyFileAttempts = 5;
        private const int BusyFileDelayMs = 60;

        private VaultSession()
        {
        }

        public string FilePath { get; private set; }

        public VaultData Data { get; private set; }

        /// <summary>Число итераций PBKDF2 или проходов Argon2id.</summary>
        public int Iterations
        {
            get { return kdf.Iterations; }
        }

        /// <summary>Как сейчас получается ключ: функция и параметры (копия).</summary>
        public KdfParameters Protection
        {
            get { return kdf.Clone(); }
        }

        /// <summary>
        /// true, если в открытых данных есть то, чего нет в файле: дописать файл при проверке
        /// не удалось либо программа перестала дописывать его сама (см. Reload).
        /// </summary>
        public bool HasUnwrittenChanges { get; private set; }

        /// <summary>
        /// Что влилось из файла с прошлого вызова — при сохранениях и проверках файла.
        /// Возвращает null, если за это время файл никто, кроме нас, не менял.
        /// </summary>
        public MergeResult TakeMerge()
        {
            lock (sync)
            {
                MergeResult result = merged;
                merged = null;
                return result;
            }
        }

        /// <summary>true, если хранилище открывается мастер-паролем вместе с ключевым файлом.</summary>
        public bool UsesKeyFile
        {
            get { return kdf.KeyFile; }
        }

        public static string BackupPath(string path)
        {
            return AtomicFile.BackupPath(path);
        }

        /// <summary>
        /// Читает только заголовок файла хранилища — чтобы до ввода пароля узнать, нужен ли
        /// ключевой файл. Возвращает null, если файла нет или это не хранилище.
        /// </summary>
        public static VaultHeader Peek(string path)
        {
            try
            {
                if (!File.Exists(path)) return null;
                byte[] head = new byte[VaultFormat.HeaderSizeV2 + Cng.TagSize];
                int read;
                using (var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    read = stream.Read(head, 0, head.Length);
                }
                if (read < head.Length) Array.Resize(ref head, read);
                return VaultFormat.ParseHeader(head);
            }
            catch (VaultException) { return null; }
            catch (IOException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (SecurityException) { return null; }
            catch (NotSupportedException) { return null; }
        }

        /// <summary>Создаёт новое пустое хранилище (Argon2id) и сразу записывает его на диск.</summary>
        public static VaultSession Create(string path, string password)
        {
            return Create(path, password, (byte[])null);
        }

        /// <summary>Создаёт новое хранилище, которое открывается паролем вместе с ключевым файлом (если он задан).</summary>
        public static VaultSession Create(string path, string password, byte[] keyFile)
        {
            return Create(path, password, keyFile, KdfParameters.Argon2(Cng.RandomBytes(VaultFormat.SaltSize), keyFile != null));
        }

        /// <summary>Создаёт хранилище прежнего формата (PBKDF2) — как это делал KeyBox 1.x.</summary>
        public static VaultSession Create(string path, string password, int iterations)
        {
            return Create(path, password, null, KdfParameters.Pbkdf2(iterations, Cng.RandomBytes(VaultFormat.SaltSize)));
        }

        private static VaultSession Create(string path, string password, byte[] keyFile, KdfParameters parameters)
        {
            if (File.Exists(path))
            {
                throw new VaultException(VaultError.Io,
                    L.F("Файл хранилища уже существует: {0}", "The vault file already exists: {0}", path));
            }

            var session = new VaultSession();
            session.FilePath = path;
            session.kdf = parameters;
            session.keyFileHash = keyFile == null ? null : VaultFormat.HashKeyFile(keyFile);
            try
            {
                session.key = VaultFormat.DeriveKey(password, session.keyFileHash, parameters);
                session.Data = VaultData.CreateEmpty();
                session.Save();
            }
            catch
            {
                session.Dispose();
                throw;
            }
            return session;
        }

        /// <summary>
        /// Открывает существующее хранилище. При неверном пароле или изменённом файле
        /// бросает <see cref="VaultException"/> с кодом WrongPassword.
        /// </summary>
        public static VaultSession Open(string path, string password)
        {
            return Open(path, password, null);
        }

        /// <param name="keyFile">Содержимое ключевого файла или null. Лишний ключевой файл не мешает.</param>
        public static VaultSession Open(string path, string password, byte[] keyFile)
        {
            byte[] file = ReadFile(path);
            VaultHeader header = VaultFormat.ParseHeader(file);

            byte[] fileHash = header.Kdf.KeyFile && keyFile != null ? VaultFormat.HashKeyFile(keyFile) : null;
            byte[] key = VaultFormat.DeriveKey(password, fileHash, header.Kdf);
            byte[] json = null;
            try
            {
                json = VaultFormat.Open(key, file);

                var session = new VaultSession();
                session.FilePath = path;
                session.Data = VaultData.FromJson(json);
                session.kdf = header.Kdf;
                session.keyFileHash = fileHash;
                session.key = key;
                session.Remember(file);
                key = null; // ключом теперь владеет сессия
                fileHash = null;
                return session;
            }
            finally
            {
                if (key != null) Array.Clear(key, 0, key.Length);
                if (fileHash != null) Array.Clear(fileHash, 0, fileHash.Length);
                if (json != null) Array.Clear(json, 0, json.Length);
            }
        }

        /// <summary>
        /// Шифрует текущие данные и записывает файл хранилища. Если файл за это время изменил
        /// кто-то ещё (другой компьютер через общую или облачную папку), его изменения сначала
        /// вливаются в открытые данные — чужая работа не затирается. Что влилось, отдаёт TakeMerge.
        /// </summary>
        public void Save()
        {
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException("VaultSession");
                HasUnwrittenChanges = true; // пока запись не удалась, изменения есть только в памяти
                MergeFromDisk();
                WriteCurrent();
                unattendedWrites = 0;
            }
        }

        /// <summary>
        /// Проверяет, не изменил ли файл кто-то ещё, и если да — вливает изменения в открытые
        /// данные. Если в них после этого есть то, чего нет в файле, файл дописывается.
        /// Возвращает true, если файл был изменён не нами и прочитан; что влилось, отдаёт TakeMerge.
        /// </summary>
        public bool Reload()
        {
            lock (sync)
            {
                if (disposed || !LooksChanged()) return false;

                byte[] disk;
                try
                {
                    disk = ReadIfChanged();
                }
                catch (VaultException)
                {
                    return false; // файл занят (его как раз пишут) — заглянем при следующей проверке
                }
                if (disk == null) return false;

                VaultData theirs = OpenForeign(disk);
                if (theirs == null)
                {
                    // Не читается: записан не до конца или испорчен. Перечитывать его при каждой
                    // проверке незачем — ждём, пока изменится снова; ближайшее сохранение его заменит.
                    RememberFileInfo();
                    return false;
                }

                Note(Data.Merge(theirs));
                if (Data.ContentEquals(theirs))
                {
                    // В файле уже есть всё, что есть у нас: переписывать его незачем.
                    Remember(disk);
                    unattendedWrites = 0;
                    HasUnwrittenChanges = false;
                }
                else if (unattendedWrites < MaxUnattendedWrites)
                {
                    // У нас есть то, чего нет в файле (например, облако оставило чужую версию
                    // вместо нашей) — дописываем, чтобы это дошло и до других компьютеров.
                    unattendedWrites++;
                    try
                    {
                        WriteCurrent();
                    }
                    catch (VaultException) { HasUnwrittenChanges = true; }
                    catch (CryptographicException) { HasUnwrittenChanges = true; }
                }
                else
                {
                    // Файл несколько раз подряд возвращается без наших изменений: кто-то упорно пишет
                    // свою версию. Чтобы две программы не переписывали файл друг за другом без конца,
                    // дальше он дописывается только при обычном сохранении.
                    Remember(disk);
                    HasUnwrittenChanges = true;
                }
                return true;
            }
        }

        /// <summary>
        /// Читает другой файл — копию этого же хранилища с тем же мастер-паролем (например,
        /// «конфликтующую копию» из облачной папки). Возвращает его данные или null, если файл
        /// зашифрован другим ключом и для него нужен свой пароль.
        /// </summary>
        public VaultData ReadCopy(string path)
        {
            byte[] file = ReadFile(path);
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException("VaultSession");
                VaultHeader header = VaultFormat.ParseHeader(file);
                if (!SameProtection(header.Kdf, kdf)) return null;

                byte[] json;
                try
                {
                    json = VaultFormat.Open(key, file);
                }
                catch (VaultException)
                {
                    return null;
                }
                try
                {
                    return VaultData.FromJson(json);
                }
                finally
                {
                    Array.Clear(json, 0, json.Length);
                }
            }
        }

        /// <summary>
        /// Записывает открытые данные (нынешним ключом) в отдельный файл рядом с хранилищем —
        /// на случай, когда сам файл хранилища перезаписывать нельзя. Возвращает путь к файлу.
        /// </summary>
        /// <param name="path">Куда писать; null — подобрать имя вида «имя.conflict-дата-время.vault».</param>
        public string SaveConflictCopy(string path)
        {
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException("VaultSession");
                if (path == null)
                {
                    string directory = Path.GetDirectoryName(FilePath) ?? "";
                    string name = Path.GetFileNameWithoutExtension(FilePath) + ".conflict-" + DateTime.Now.ToString("yyyyMMdd-HHmmss");
                    string extension = Path.GetExtension(FilePath);
                    path = Path.Combine(directory, name + extension);
                    for (int n = 2; File.Exists(path); n++)
                    {
                        path = Path.Combine(directory, name + "-" + n + extension);
                    }
                }

                byte[] json = Data.ToJson();
                try
                {
                    WriteFile(path, VaultFormat.Seal(key, kdf, json));
                }
                finally
                {
                    Array.Clear(json, 0, json.Length);
                }
                return path;
            }
        }

        /// <summary>Шифрует текущие данные и записывает файл, не заглядывая в то, что сейчас лежит на диске.</summary>
        private void WriteCurrent()
        {
            byte[] json = Data.ToJson();
            try
            {
                byte[] file = VaultFormat.Seal(key, kdf, json);
                WriteFile(FilePath, file);
                Remember(file);
                HasUnwrittenChanges = false;
            }
            finally
            {
                Array.Clear(json, 0, json.Length);
            }
        }

        /// <summary>Если файл на диске изменил кто-то ещё, вливает его содержимое в открытые данные.</summary>
        private void MergeFromDisk()
        {
            byte[] disk;
            for (int attempt = 1; ; attempt++)
            {
                try
                {
                    disk = ReadIfChanged();
                    break;
                }
                catch (VaultException ex)
                {
                    // Файл такого размера хранилищем быть не может: беречь в нём нечего.
                    if (ex.Error == VaultError.BadFormat) return;

                    // Файл может быть занят на мгновение — его как раз записывает облачная папка
                    // или проверяет антивирус. Немного ждём, прежде чем сообщать о сбое.
                    if (attempt >= BusyFileAttempts) throw;
                    Thread.Sleep(BusyFileDelayMs);
                }
            }
            if (disk == null) return;

            // Файл, который не читается нашим же ключом, записан не до конца или испорчен: беречь
            // в нём нечего, он будет заменён (а сам останется рядом как резервная копия).
            VaultData theirs = OpenForeign(disk);
            if (theirs != null) Note(Data.Merge(theirs));
        }

        private void Note(MergeResult result)
        {
            if (merged == null) merged = result;
            else merged.Add(result);
        }

        /// <summary>Содержимое файла, если оно не то, что эта сессия читала или писала; иначе null.</summary>
        private byte[] ReadIfChanged()
        {
            if (!File.Exists(FilePath)) return null;
            byte[] disk = ReadFile(FilePath);
            if (fileHash != null && SameBytes(Hash(disk), fileHash))
            {
                RememberFileInfo();
                return null;
            }
            return disk;
        }

        /// <summary>
        /// Расшифровывает файл, изменённый не нами. Возвращает null, если он не читается вовсе.
        /// Бросает исключение, если его нельзя ни прочитать нашим ключом, ни затереть: там сменили
        /// пароль или защиту либо его записала более новая версия программы.
        /// </summary>
        private VaultData OpenForeign(byte[] disk)
        {
            VaultHeader header;
            try
            {
                header = VaultFormat.ParseHeader(disk);
            }
            catch (VaultException ex)
            {
                if (ex.Error == VaultError.UnsupportedVersion) throw NewerVersion(ex);
                return null;
            }

            if (!SameProtection(header.Kdf, kdf))
            {
                throw new VaultException(VaultError.Conflict,
                    L.T("Файл хранилища изменён в другом месте, и нынешним ключом он уже не открывается: похоже, там сменили мастер-пароль или защиту.",
                        "The vault file was changed elsewhere and can no longer be opened with the current key: it looks like the master password or the protection was changed there."));
            }

            byte[] json;
            try
            {
                json = VaultFormat.Open(key, disk);
            }
            catch (VaultException)
            {
                return null;
            }

            try
            {
                return VaultData.FromJson(json);
            }
            catch (VaultException ex)
            {
                if (ex.Error == VaultError.UnsupportedVersion) throw NewerVersion(ex);
                return null;
            }
            finally
            {
                Array.Clear(json, 0, json.Length);
            }
        }

        private static VaultException NewerVersion(Exception inner)
        {
            return new VaultException(VaultError.Conflict,
                L.T("Файл хранилища изменён более новой версией KeyBox: эта версия не может его прочитать и не станет его перезаписывать. Обновите программу.",
                    "The vault file was changed by a newer version of KeyBox: this version cannot read it and will not overwrite it. Update the program."),
                inner);
        }

        private static bool SameProtection(KdfParameters a, KdfParameters b)
        {
            return a.Kdf == b.Kdf && a.Iterations == b.Iterations && a.MemoryKiB == b.MemoryKiB &&
                   a.Parallelism == b.Parallelism && a.KeyFile == b.KeyFile && SameBytes(a.Salt, b.Salt);
        }

        private void Remember(byte[] file)
        {
            fileHash = Hash(file);
            RememberFileInfo();
        }

        private void RememberFileInfo()
        {
            try
            {
                var info = new FileInfo(FilePath);
                seenLength = info.Exists ? info.Length : -1;
                seenTime = info.Exists ? info.LastWriteTimeUtc : DateTime.MinValue;
            }
            catch (IOException) { seenLength = -1; }
            catch (UnauthorizedAccessException) { seenLength = -1; }
            catch (SecurityException) { seenLength = -1; }
        }

        /// <summary>Быстрая проверка без чтения файла: изменились ли его размер или время записи.</summary>
        private bool LooksChanged()
        {
            try
            {
                var info = new FileInfo(FilePath);
                return info.Exists && (info.Length != seenLength || info.LastWriteTimeUtc != seenTime);
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
            catch (SecurityException) { return false; }
        }

        private static byte[] Hash(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(data);
            }
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        /// <summary>Проверяет, что пароль — действующий мастер-пароль этого хранилища.</summary>
        public bool VerifyPassword(string password)
        {
            KdfParameters current;
            byte[] currentFileHash;
            lock (sync)
            {
                if (disposed) return false;
                current = kdf.Clone();
                currentFileHash = keyFileHash == null ? null : (byte[])keyFileHash.Clone();
            }

            byte[] candidate = VaultFormat.DeriveKey(password, currentFileHash, current);
            try
            {
                lock (sync)
                {
                    return !disposed && FixedTimeEquals(candidate, key);
                }
            }
            finally
            {
                Array.Clear(candidate, 0, candidate.Length);
                if (currentFileHash != null) Array.Clear(currentFileHash, 0, currentFileHash.Length);
            }
        }

        /// <summary>
        /// Меняет мастер-пароль: новая соль, новый ключ, файл перезаписывается. Ключевой файл,
        /// если он используется, остаётся прежним. Хранилище прежнего формата заодно переводится
        /// на Argon2id. Если запись не удалась, сессия остаётся на прежнем ключе.
        /// </summary>
        public void ChangePassword(string newPassword)
        {
            ChangeProtection(newPassword, UsesKeyFile, null);
        }

        /// <summary>
        /// Перешифровывает хранилище с новой защитой: мастер-пароль (новый или прежний) и ключевой
        /// файл. Функция получения ключа всегда становится Argon2id с параметрами по умолчанию.
        /// </summary>
        /// <param name="password">Мастер-пароль, которым хранилище будет открываться.</param>
        /// <param name="useKeyFile">Нужен ли будет ключевой файл.</param>
        /// <param name="newKeyFile">Содержимое нового ключевого файла; null — оставить нынешний.</param>
        public void ChangeProtection(string password, bool useKeyFile, byte[] newKeyFile)
        {
            byte[] newFileHash = null;
            if (useKeyFile)
            {
                if (newKeyFile != null)
                {
                    newFileHash = VaultFormat.HashKeyFile(newKeyFile);
                }
                else
                {
                    lock (sync)
                    {
                        if (disposed) throw new ObjectDisposedException("VaultSession");
                        if (keyFileHash == null) throw new InvalidOperationException("There is no key file to keep.");
                        newFileHash = (byte[])keyFileHash.Clone();
                    }
                }
            }

            KdfParameters newKdf = KdfParameters.Argon2(Cng.RandomBytes(VaultFormat.SaltSize), useKeyFile);
            byte[] newKey = VaultFormat.DeriveKey(password, newFileHash, newKdf);

            lock (sync)
            {
                if (disposed)
                {
                    Array.Clear(newKey, 0, newKey.Length);
                    throw new ObjectDisposedException("VaultSession");
                }

                // Если файл успели изменить в другом месте, его изменения вливаются сейчас,
                // пока он ещё открывается прежним ключом.
                try
                {
                    MergeFromDisk();
                }
                catch
                {
                    Array.Clear(newKey, 0, newKey.Length);
                    throw;
                }

                byte[] oldKey = key;
                byte[] oldFileHash = keyFileHash;
                KdfParameters oldKdf = kdf;

                key = newKey;
                keyFileHash = newFileHash;
                kdf = newKdf;
                try
                {
                    WriteCurrent();
                }
                catch
                {
                    key = oldKey;
                    keyFileHash = oldFileHash;
                    kdf = oldKdf;
                    Array.Clear(newKey, 0, newKey.Length);
                    throw;
                }
                Array.Clear(oldKey, 0, oldKey.Length);
                if (oldFileHash != null) Array.Clear(oldFileHash, 0, oldFileHash.Length);
                unattendedWrites = 0;

                // Резервная копия осталась зашифрованной прежним ключом. Заменяем её копией нового
                // файла, чтобы прежний пароль (и прежний ключевой файл) больше ничего не открывал.
                string backup = BackupPath(FilePath);
                try
                {
                    File.Copy(FilePath, backup, true);
                }
                catch (IOException)
                {
                    AtomicFile.TryDelete(backup);
                }
                catch (UnauthorizedAccessException)
                {
                    AtomicFile.TryDelete(backup);
                }
            }
        }

        public void Dispose()
        {
            lock (sync)
            {
                if (disposed) return;
                disposed = true;
                if (key != null) Array.Clear(key, 0, key.Length);
                if (keyFileHash != null) Array.Clear(keyFileHash, 0, keyFileHash.Length);
                key = null;
                keyFileHash = null;
                Data = null;
            }
        }

        /// <summary>Читает ключевой файл целиком. Слишком большой файл ключевым быть не может.</summary>
        public static byte[] ReadKeyFile(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists)
                {
                    throw new VaultException(VaultError.Io,
                        L.F("Ключевой файл не найден: {0}", "The key file was not found: {0}", path));
                }
                if (info.Length == 0 || info.Length > VaultFormat.MaxKeyFileSize)
                {
                    throw new VaultException(VaultError.Io,
                        L.T("Этот файл не годится в ключевые: он пуст или слишком велик.", "This file cannot be a key file: it is empty or too large."));
                }
                return File.ReadAllBytes(path);
            }
            catch (IOException ex) { throw KeyFileFailed(ex); }
            catch (UnauthorizedAccessException ex) { throw KeyFileFailed(ex); }
            catch (SecurityException ex) { throw KeyFileFailed(ex); }
            catch (NotSupportedException ex) { throw KeyFileFailed(ex); }
            catch (ArgumentException ex) { throw KeyFileFailed(ex); }
        }

        private static byte[] ReadFile(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists)
                {
                    throw new VaultException(VaultError.Io,
                        L.F("Файл хранилища не найден: {0}", "The vault file was not found: {0}", path));
                }
                if (info.Length > VaultFormat.MaxFileSize)
                {
                    throw new VaultException(VaultError.BadFormat, L.T("Файл слишком велик для хранилища KeyBox.", "The file is too large to be a KeyBox vault."));
                }
                return File.ReadAllBytes(path);
            }
            catch (IOException ex) { throw ReadFailed(ex); }
            catch (UnauthorizedAccessException ex) { throw ReadFailed(ex); }
            catch (SecurityException ex) { throw ReadFailed(ex); }
            catch (NotSupportedException ex) { throw ReadFailed(ex); }
        }

        private static void WriteFile(string path, byte[] content)
        {
            try
            {
                string directory = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
                AtomicFile.Write(path, content);
            }
            catch (IOException ex) { throw WriteFailed(ex); }
            catch (UnauthorizedAccessException ex) { throw WriteFailed(ex); }
            catch (SecurityException ex) { throw WriteFailed(ex); }
            catch (NotSupportedException ex) { throw WriteFailed(ex); }
        }

        private static VaultException ReadFailed(Exception ex)
        {
            return new VaultException(VaultError.Io, L.T("Не удалось прочитать файл хранилища. ", "Could not read the vault file. ") + ex.Message, ex);
        }

        private static VaultException WriteFailed(Exception ex)
        {
            return new VaultException(VaultError.Io, L.T("Не удалось записать файл хранилища. ", "Could not write the vault file. ") + ex.Message, ex);
        }

        private static VaultException KeyFileFailed(Exception ex)
        {
            return new VaultException(VaultError.Io, L.T("Не удалось прочитать ключевой файл. ", "Could not read the key file. ") + ex.Message, ex);
        }

        private static bool FixedTimeEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int difference = 0;
            for (int i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }
            return difference == 0;
        }
    }
}
