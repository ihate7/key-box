using System;
using System.Security.Cryptography;
using System.Text;
using KeyBox.Crypto;

namespace KeyBox.Vault
{
    internal enum VaultError
    {
        /// <summary>Файл не является хранилищем KeyBox или его структура нарушена.</summary>
        BadFormat,

        /// <summary>Хранилище создано более новой версией программы.</summary>
        UnsupportedVersion,

        /// <summary>Неверный мастер-пароль (или ключевой файл) либо файл изменён или повреждён.</summary>
        WrongPassword,

        /// <summary>Ошибка чтения или записи файла.</summary>
        Io,

        /// <summary>Хранилище открывается с ключевым файлом, а он не указан.</summary>
        KeyFileRequired
    }

    /// <summary>Ошибка работы с хранилищем. Текст можно показывать пользователю.</summary>
    internal sealed class VaultException : Exception
    {
        public VaultError Error { get; private set; }

        public VaultException(VaultError error, string message)
            : base(message)
        {
            Error = error;
        }

        public VaultException(VaultError error, string message, Exception inner)
            : base(message, inner)
        {
            Error = error;
        }
    }

    /// <summary>
    /// Как из мастер-пароля получается ключ шифрования: функция, её параметры и соль.
    /// Всё это не секрет и хранится в заголовке файла открыто.
    /// </summary>
    internal sealed class KdfParameters
    {
        /// <summary>1 — PBKDF2-HMAC-SHA512, 2 — Argon2id.</summary>
        public byte Kdf;

        /// <summary>PBKDF2: число итераций. Argon2id: число проходов по памяти.</summary>
        public int Iterations;

        /// <summary>Argon2id: объём памяти в кибибайтах. Для PBKDF2 — 0.</summary>
        public int MemoryKiB;

        /// <summary>Argon2id: число параллельных дорожек. Для PBKDF2 — 0.</summary>
        public int Parallelism;

        /// <summary>true — кроме мастер-пароля нужен ключевой файл.</summary>
        public bool KeyFile;

        public byte[] Salt;

        public bool IsArgon2
        {
            get { return Kdf == VaultFormat.KdfArgon2id; }
        }

        public static KdfParameters Pbkdf2(int iterations, byte[] salt)
        {
            var parameters = new KdfParameters();
            parameters.Kdf = VaultFormat.KdfPbkdf2Sha512;
            parameters.Iterations = iterations;
            parameters.Salt = salt;
            return parameters;
        }

        /// <summary>Argon2id с параметрами по умолчанию (рекомендация RFC 9106 для ограниченной памяти).</summary>
        public static KdfParameters Argon2(byte[] salt, bool keyFile)
        {
            var parameters = new KdfParameters();
            parameters.Kdf = VaultFormat.KdfArgon2id;
            parameters.Iterations = Argon2id.DefaultPasses;
            parameters.MemoryKiB = Argon2id.DefaultMemoryKiB;
            parameters.Parallelism = Argon2id.DefaultParallelism;
            parameters.KeyFile = keyFile;
            parameters.Salt = salt;
            return parameters;
        }

        public KdfParameters Clone()
        {
            var copy = (KdfParameters)MemberwiseClone();
            copy.Salt = Salt == null ? null : (byte[])Salt.Clone();
            return copy;
        }

        /// <summary>Описание для пользователя: «Argon2id (64 МиБ памяти, проходов: 3, потоков: 4)».</summary>
        public string Describe()
        {
            if (IsArgon2)
            {
                return L.F("Argon2id ({0} МиБ памяти, проходов: {1}, потоков: {2})", "Argon2id ({0} MiB of memory, passes: {1}, threads: {2})",
                    MemoryKiB / 1024, Iterations, Parallelism);
            }
            return L.F("PBKDF2-HMAC-SHA512 ({0} итераций)", "PBKDF2-HMAC-SHA512 ({0} iterations)", Iterations.ToString("N0"));
        }
    }

    internal sealed class VaultHeader
    {
        /// <summary>Версия формата файла: 1 или 2.</summary>
        public int FormatVersion;

        /// <summary>Размер заголовка в байтах (он же — начало шифртекста).</summary>
        public int Size;

        public KdfParameters Kdf;
        public byte[] Nonce;

        public int Iterations
        {
            get { return Kdf.Iterations; }
        }

        public byte[] Salt
        {
            get { return Kdf.Salt; }
        }
    }

    /// <summary>
    /// Формат файла хранилища. Все числа — little-endian.
    ///
    /// Версия 2 (её пишет программа для новых хранилищ):
    ///
    ///   смещение  размер  поле
    ///   0         6       сигнатура "KEYBOX" (ASCII)
    ///   6         2       версия формата = 2
    ///   8         1       функция получения ключа: 1 = PBKDF2-HMAC-SHA512, 2 = Argon2id
    ///   9         1       шифр: 1 = AES-256-GCM
    ///   10        1       признаки: бит 0 — нужен ключевой файл
    ///   11        1       резерв = 0
    ///   12        4       PBKDF2: число итераций; Argon2id: число проходов
    ///   16        4       Argon2id: память в кибибайтах; PBKDF2: 0
    ///   20        4       Argon2id: число дорожек (потоков); PBKDF2: 0
    ///   24        32      соль
    ///   56        12      nonce GCM (новый при каждом сохранении)
    ///   68        N       шифртекст
    ///   68+N      16      тег аутентификации GCM
    ///
    /// Версия 1 (хранилища, созданные KeyBox 1.x; читается и записывается как раньше, пока
    /// хранилище не перевели на Argon2id или ключевой файл):
    ///
    ///   0   6   "KEYBOX"        10  4   число итераций PBKDF2
    ///   6   2   версия = 1      14  32  соль
    ///   8   1   KDF = 1         46  12  nonce
    ///   9   1   шифр = 1        58  N   шифртекст, затем 16 байт тега
    ///
    /// Секрет для функции получения ключа — мастер-пароль в UTF-8 (в форме Юникода NFC).
    /// С ключевым файлом секрет другой: HMAC-SHA512(ключ = SHA-512(содержимое файла), данные = пароль).
    /// Ключ шифрования — 32 байта. Открытый текст — JSON в UTF-8. Весь заголовок передаётся
    /// в GCM как дополнительные аутентифицируемые данные, поэтому его подмена обнаруживается.
    /// </summary>
    internal static class VaultFormat
    {
        /// <summary>Самая новая версия формата, которую понимает программа.</summary>
        public const int FormatVersion = 2;

        public const byte KdfPbkdf2Sha512 = 1;
        public const byte KdfArgon2id = 2;
        public const byte CipherAes256Gcm = 1;

        public const int SaltSize = 32;

        /// <summary>Размер заголовка версии 1.</summary>
        public const int HeaderSize = 58;

        /// <summary>Размер заголовка версии 2.</summary>
        public const int HeaderSizeV2 = 68;

        private const byte FlagKeyFile = 0x01;

        /// <summary>Число итераций PBKDF2 для хранилищ прежнего формата.</summary>
        public const int DefaultIterations = 600000;

        // Границы для значений из файла: они читаются до проверки подлинности, поэтому чужой
        // или испорченный файл не должен «подвесить» программу или занять всю память.
        public const int MinIterations = 1000;
        public const int MaxIterations = 20000000;
        public const int MaxArgon2MemoryKiB = 1024 * 1024;
        public const int MaxArgon2Passes = 64;
        public const int MaxArgon2Parallelism = 64;

        /// <summary>Наибольшая «работа» Argon2id (память × проходы), примерно в 20 раз больше обычной.</summary>
        public const long MaxArgon2Work = 4L * 1024 * 1024;

        public const int MaxFileSize = 256 * 1024 * 1024;

        /// <summary>Ключевым файлом может быть любой файл не больше этого размера.</summary>
        public const int MaxKeyFileSize = 16 * 1024 * 1024;

        /// <summary>Размер ключевого файла, который создаёт сама программа.</summary>
        public const int NewKeyFileSize = 64;

        private static readonly byte[] Magic =
        {
            (byte)'K', (byte)'E', (byte)'Y', (byte)'B', (byte)'O', (byte)'X'
        };

        // ---------- Ключ ----------

        /// <summary>Получает ключ шифрования из мастер-пароля функцией PBKDF2 (хранилища прежнего формата).</summary>
        public static byte[] DeriveKey(string password, byte[] salt, int iterations)
        {
            return DeriveKey(password, null, KdfParameters.Pbkdf2(iterations, salt));
        }

        /// <summary>Получает ключ шифрования из мастер-пароля и, если он используется, ключевого файла.</summary>
        /// <param name="password">Мастер-пароль.</param>
        /// <param name="keyFileHash">SHA-512 ключевого файла (см. HashKeyFile) или null.</param>
        /// <param name="kdf">Функция, параметры и соль.</param>
        public static byte[] DeriveKey(string password, byte[] keyFileHash, KdfParameters kdf)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (kdf == null) throw new ArgumentNullException("kdf");
            if (kdf.KeyFile && keyFileHash == null)
            {
                throw new VaultException(VaultError.KeyFileRequired,
                    L.T("Это хранилище открывается мастер-паролем вместе с ключевым файлом. Укажите ключевой файл.",
                        "This vault is opened with the master password together with a key file. Choose the key file."));
            }

            byte[] secret = Secret(password, kdf.KeyFile ? keyFileHash : null);
            try
            {
                if (kdf.IsArgon2)
                {
                    return Argon2id.Hash(secret, kdf.Salt, kdf.Iterations, kdf.MemoryKiB, kdf.Parallelism, Cng.KeySize);
                }
                return Cng.Pbkdf2Sha512(secret, kdf.Salt, kdf.Iterations, Cng.KeySize);
            }
            catch (OutOfMemoryException)
            {
                throw new VaultException(VaultError.Io,
                    L.F("Не хватило памяти: чтобы открыть это хранилище, нужно {0} МиБ свободной памяти.",
                        "Out of memory: opening this vault needs {0} MiB of free memory.", kdf.MemoryKiB / 1024));
            }
            finally
            {
                Array.Clear(secret, 0, secret.Length);
            }
        }

        /// <summary>SHA-512 от содержимого ключевого файла: в таком виде он участвует в получении ключа.</summary>
        public static byte[] HashKeyFile(byte[] content)
        {
            if (content == null) throw new ArgumentNullException("content");
            using (SHA512 sha = SHA512.Create())
            {
                return sha.ComputeHash(content);
            }
        }

        /// <summary>Содержимое нового ключевого файла: случайные байты.</summary>
        public static byte[] NewKeyFile()
        {
            return Cng.RandomBytes(NewKeyFileSize);
        }

        private static byte[] Secret(string password, byte[] keyFileHash)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(NormalizePassword(password));
            if (keyFileHash == null) return bytes;

            try
            {
                using (var hmac = new HMACSHA512(keyFileHash))
                {
                    return hmac.ComputeHash(bytes);
                }
            }
            finally
            {
                Array.Clear(bytes, 0, bytes.Length);
            }
        }

        /// <summary>
        /// Один и тот же пароль с разных клавиатур и систем может прийти в разных
        /// формах Юникода (например, «й» одним символом или двумя) — приводим к NFC.
        /// </summary>
        private static string NormalizePassword(string password)
        {
            try
            {
                return password.Normalize(NormalizationForm.FormC);
            }
            catch (ArgumentException)
            {
                return password;
            }
        }

        // ---------- Запись ----------

        /// <summary>Шифрует данные и собирает файл хранилища прежнего формата (PBKDF2, без ключевого файла).</summary>
        public static byte[] Seal(byte[] key, byte[] salt, int iterations, byte[] plaintext)
        {
            return Seal(key, KdfParameters.Pbkdf2(iterations, salt), plaintext);
        }

        /// <summary>
        /// Шифрует данные и собирает файл хранилища целиком. Хранилище на PBKDF2 без ключевого
        /// файла записывается в формате версии 1 — его по-прежнему открывают прежние версии программы.
        /// </summary>
        public static byte[] Seal(byte[] key, KdfParameters kdf, byte[] plaintext)
        {
            if (kdf == null) throw new ArgumentNullException("kdf");
            if (kdf.Salt == null || kdf.Salt.Length != SaltSize) throw new ArgumentException("Invalid salt size.", "kdf");
            if (!IsAcceptable(kdf)) throw new ArgumentOutOfRangeException("kdf");

            byte[] nonce = Cng.RandomBytes(Cng.NonceSize);
            byte[] header;
            if (kdf.Kdf == KdfPbkdf2Sha512 && !kdf.KeyFile)
            {
                header = new byte[HeaderSize];
                Buffer.BlockCopy(Magic, 0, header, 0, Magic.Length);
                header[6] = 1;
                header[8] = KdfPbkdf2Sha512;
                header[9] = CipherAes256Gcm;
                WriteInt32(header, 10, kdf.Iterations);
                Buffer.BlockCopy(kdf.Salt, 0, header, 14, SaltSize);
                Buffer.BlockCopy(nonce, 0, header, 14 + SaltSize, Cng.NonceSize);
            }
            else
            {
                header = new byte[HeaderSizeV2];
                Buffer.BlockCopy(Magic, 0, header, 0, Magic.Length);
                header[6] = 2;
                header[8] = kdf.Kdf;
                header[9] = CipherAes256Gcm;
                header[10] = kdf.KeyFile ? FlagKeyFile : (byte)0;
                WriteInt32(header, 12, kdf.Iterations);
                WriteInt32(header, 16, kdf.IsArgon2 ? kdf.MemoryKiB : 0);
                WriteInt32(header, 20, kdf.IsArgon2 ? kdf.Parallelism : 0);
                Buffer.BlockCopy(kdf.Salt, 0, header, 24, SaltSize);
                Buffer.BlockCopy(nonce, 0, header, 24 + SaltSize, Cng.NonceSize);
            }

            byte[] tag;
            byte[] ciphertext = Cng.AesGcmEncrypt(key, nonce, plaintext, header, out tag);

            byte[] file = new byte[header.Length + ciphertext.Length + Cng.TagSize];
            Buffer.BlockCopy(header, 0, file, 0, header.Length);
            Buffer.BlockCopy(ciphertext, 0, file, header.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, file, header.Length + ciphertext.Length, Cng.TagSize);
            return file;
        }

        // ---------- Чтение ----------

        /// <summary>Разбирает и проверяет заголовок файла.</summary>
        public static VaultHeader ParseHeader(byte[] file)
        {
            if (file == null || file.Length < HeaderSize + Cng.TagSize) throw NotAVault();
            for (int i = 0; i < Magic.Length; i++)
            {
                if (file[i] != Magic[i]) throw NotAVault();
            }

            int version = file[6] | (file[7] << 8);
            if (version > FormatVersion) throw NewerVersion();
            if (version != 1 && version != 2) throw NotAVault();

            var header = new VaultHeader();
            header.FormatVersion = version;
            header.Kdf = new KdfParameters();

            if (file[9] != CipherAes256Gcm) throw UnknownAlgorithm();

            int saltAt;
            if (version == 1)
            {
                if (file[8] != KdfPbkdf2Sha512) throw UnknownAlgorithm();
                header.Size = HeaderSize;
                header.Kdf.Kdf = KdfPbkdf2Sha512;
                header.Kdf.Iterations = ReadCount(file, 10);
                saltAt = 14;
            }
            else
            {
                if (file.Length < HeaderSizeV2 + Cng.TagSize) throw NotAVault();
                if (file[8] != KdfPbkdf2Sha512 && file[8] != KdfArgon2id) throw UnknownAlgorithm();
                // Незнакомые признаки и занятый резерв означают возможности, о которых эта версия не знает.
                if ((file[10] & ~FlagKeyFile) != 0 || file[11] != 0) throw NewerVersion();

                header.Size = HeaderSizeV2;
                header.Kdf.Kdf = file[8];
                header.Kdf.KeyFile = (file[10] & FlagKeyFile) != 0;
                header.Kdf.Iterations = ReadCount(file, 12);
                header.Kdf.MemoryKiB = ReadCount(file, 16);
                header.Kdf.Parallelism = ReadCount(file, 20);
                saltAt = 24;
            }

            if (!IsAcceptable(header.Kdf)) throw NotAVault();

            header.Kdf.Salt = Slice(file, saltAt, SaltSize);
            header.Nonce = Slice(file, saltAt + SaltSize, Cng.NonceSize);
            return header;
        }

        /// <summary>
        /// Расшифровывает файл хранилища готовым ключом.
        /// Бросает <see cref="VaultException"/> с кодом WrongPassword, если ключ не подошёл
        /// или файл был изменён.
        /// </summary>
        public static byte[] Open(byte[] key, byte[] file)
        {
            VaultHeader header = ParseHeader(file);

            byte[] associatedData = Slice(file, 0, header.Size);
            byte[] ciphertext = Slice(file, header.Size, file.Length - header.Size - Cng.TagSize);
            byte[] tag = Slice(file, file.Length - Cng.TagSize, Cng.TagSize);

            byte[] plaintext;
            if (!Cng.AesGcmDecrypt(key, header.Nonce, ciphertext, associatedData, tag, out plaintext))
            {
                throw new VaultException(VaultError.WrongPassword, header.Kdf.KeyFile
                    ? L.T("Неверный мастер-пароль или ключевой файл, либо файл хранилища повреждён.",
                          "Wrong master password or key file, or the vault file is damaged.")
                    : L.T("Неверный мастер-пароль или файл хранилища повреждён.", "Wrong master password, or the vault file is damaged."));
            }
            return plaintext;
        }

        /// <summary>Параметры получения ключа в допустимых границах.</summary>
        private static bool IsAcceptable(KdfParameters kdf)
        {
            if (kdf.Kdf == KdfPbkdf2Sha512)
            {
                return kdf.Iterations >= MinIterations && kdf.Iterations <= MaxIterations && kdf.MemoryKiB == 0 && kdf.Parallelism == 0;
            }
            if (kdf.Kdf == KdfArgon2id)
            {
                return kdf.Iterations >= 1 && kdf.Iterations <= MaxArgon2Passes &&
                       kdf.Parallelism >= 1 && kdf.Parallelism <= MaxArgon2Parallelism &&
                       kdf.MemoryKiB >= Argon2id.MinMemoryKiB * kdf.Parallelism && kdf.MemoryKiB <= MaxArgon2MemoryKiB &&
                       (long)kdf.MemoryKiB * kdf.Iterations <= MaxArgon2Work;
            }
            return false;
        }

        /// <summary>Читает неотрицательное 32-разрядное число; слишком большое превращается в −1 и будет отвергнуто.</summary>
        private static int ReadCount(byte[] file, int offset)
        {
            uint value = (uint)(file[offset] | (file[offset + 1] << 8) | (file[offset + 2] << 16) | (file[offset + 3] << 24));
            return value > int.MaxValue ? -1 : (int)value;
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
        {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
        }

        private static VaultException NotAVault()
        {
            return new VaultException(VaultError.BadFormat,
                L.T("Файл не является хранилищем KeyBox или повреждён.", "The file is not a KeyBox vault, or it is damaged."));
        }

        private static VaultException NewerVersion()
        {
            return new VaultException(VaultError.UnsupportedVersion,
                L.T("Хранилище создано более новой версией KeyBox. Обновите программу.", "The vault was created by a newer version of KeyBox. Update the program."));
        }

        private static VaultException UnknownAlgorithm()
        {
            return new VaultException(VaultError.UnsupportedVersion,
                L.T("Хранилище зашифровано алгоритмом, который эта версия KeyBox не поддерживает.", "The vault is encrypted with an algorithm that this version of KeyBox does not support."));
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }
    }
}
