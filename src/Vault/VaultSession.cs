using System;
using System.IO;
using System.Security;
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

        /// <summary>Шифрует текущие данные и записывает файл хранилища.</summary>
        public void Save()
        {
            lock (sync)
            {
                if (disposed) throw new ObjectDisposedException("VaultSession");

                byte[] json = Data.ToJson();
                try
                {
                    byte[] file = VaultFormat.Seal(key, kdf, json);
                    WriteFile(FilePath, file);
                }
                finally
                {
                    Array.Clear(json, 0, json.Length);
                }
            }
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

                byte[] oldKey = key;
                byte[] oldFileHash = keyFileHash;
                KdfParameters oldKdf = kdf;

                key = newKey;
                keyFileHash = newFileHash;
                kdf = newKdf;
                try
                {
                    Save();
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
