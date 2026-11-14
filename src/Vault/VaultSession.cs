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
        private byte[] salt;
        private int iterations;
        private bool disposed;

        private VaultSession()
        {
        }

        public string FilePath { get; private set; }

        public VaultData Data { get; private set; }

        public int Iterations
        {
            get { return iterations; }
        }

        public static string BackupPath(string path)
        {
            return AtomicFile.BackupPath(path);
        }

        /// <summary>Создаёт новое пустое хранилище и сразу записывает его на диск.</summary>
        public static VaultSession Create(string path, string password)
        {
            return Create(path, password, VaultFormat.DefaultIterations);
        }

        public static VaultSession Create(string path, string password, int iterations)
        {
            if (File.Exists(path))
            {
                throw new VaultException(VaultError.Io, "Файл хранилища уже существует: " + path);
            }

            var session = new VaultSession();
            session.FilePath = path;
            session.iterations = iterations;
            session.salt = Cng.RandomBytes(VaultFormat.SaltSize);
            session.key = VaultFormat.DeriveKey(password, session.salt, iterations);
            session.Data = VaultData.CreateEmpty();
            try
            {
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
            byte[] file = ReadFile(path);
            VaultHeader header = VaultFormat.ParseHeader(file);

            byte[] key = VaultFormat.DeriveKey(password, header.Salt, header.Iterations);
            byte[] json = null;
            try
            {
                json = VaultFormat.Open(key, file);

                var session = new VaultSession();
                session.FilePath = path;
                session.Data = VaultData.FromJson(json);
                session.salt = header.Salt;
                session.iterations = header.Iterations;
                session.key = key;
                key = null; // ключом теперь владеет сессия
                return session;
            }
            finally
            {
                if (key != null) Array.Clear(key, 0, key.Length);
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
                    byte[] file = VaultFormat.Seal(key, salt, iterations, json);
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
            byte[] currentSalt;
            int currentIterations;
            lock (sync)
            {
                if (disposed) return false;
                currentSalt = salt;
                currentIterations = iterations;
            }

            byte[] candidate = VaultFormat.DeriveKey(password, currentSalt, currentIterations);
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
            }
        }

        /// <summary>
        /// Меняет мастер-пароль: новая соль, новый ключ, файл перезаписывается.
        /// Если запись не удалась, сессия остаётся на прежнем ключе.
        /// </summary>
        public void ChangePassword(string newPassword)
        {
            int newIterations = Math.Max(iterations, VaultFormat.DefaultIterations);
            byte[] newSalt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] newKey = VaultFormat.DeriveKey(newPassword, newSalt, newIterations);

            lock (sync)
            {
                if (disposed)
                {
                    Array.Clear(newKey, 0, newKey.Length);
                    throw new ObjectDisposedException("VaultSession");
                }

                byte[] oldKey = key;
                byte[] oldSalt = salt;
                int oldIterations = iterations;

                key = newKey;
                salt = newSalt;
                iterations = newIterations;
                try
                {
                    Save();
                }
                catch
                {
                    key = oldKey;
                    salt = oldSalt;
                    iterations = oldIterations;
                    Array.Clear(newKey, 0, newKey.Length);
                    throw;
                }
                Array.Clear(oldKey, 0, oldKey.Length);

                // Резервная копия осталась зашифрованной старым паролем. Заменяем её
                // копией нового файла, чтобы старый пароль больше ничего не открывал.
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
                key = null;
                salt = null;
                Data = null;
            }
        }

        private static byte[] ReadFile(string path)
        {
            try
            {
                var info = new FileInfo(path);
                if (!info.Exists)
                {
                    throw new VaultException(VaultError.Io, "Файл хранилища не найден: " + path);
                }
                if (info.Length > VaultFormat.MaxFileSize)
                {
                    throw new VaultException(VaultError.BadFormat, "Файл слишком велик для хранилища KeyBox.");
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
            return new VaultException(VaultError.Io, "Не удалось прочитать файл хранилища. " + ex.Message, ex);
        }

        private static VaultException WriteFailed(Exception ex)
        {
            return new VaultException(VaultError.Io, "Не удалось записать файл хранилища. " + ex.Message, ex);
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
