using System;
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

        /// <summary>Неверный мастер-пароль либо файл изменён или повреждён.</summary>
        WrongPassword,

        /// <summary>Ошибка чтения или записи файла.</summary>
        Io
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

    internal sealed class VaultHeader
    {
        public int Iterations;
        public byte[] Salt;
        public byte[] Nonce;
    }

    /// <summary>
    /// Формат файла хранилища, версия 1. Все числа — little-endian.
    ///
    ///   смещение  размер  поле
    ///   0         6       сигнатура "KEYBOX" (ASCII)
    ///   6         2       версия формата = 1
    ///   8         1       KDF: 1 = PBKDF2-HMAC-SHA512
    ///   9         1       шифр: 1 = AES-256-GCM
    ///   10        4       число итераций KDF
    ///   14        32      соль KDF
    ///   46        12      nonce GCM (новый при каждом сохранении)
    ///   58        N       шифртекст
    ///   58+N      16      тег аутентификации GCM
    ///
    /// Ключ: PBKDF2-HMAC-SHA512(UTF-8 от пароля в форме NFC, соль, итерации) → 32 байта.
    /// Открытый текст — JSON в UTF-8. Весь заголовок (первые 58 байт) передаётся в GCM
    /// как дополнительные аутентифицируемые данные, поэтому его подмена обнаруживается.
    /// </summary>
    internal static class VaultFormat
    {
        public const int FormatVersion = 1;
        public const byte KdfPbkdf2Sha512 = 1;
        public const byte CipherAes256Gcm = 1;

        public const int SaltSize = 32;
        public const int HeaderSize = 58;

        /// <summary>Число итераций PBKDF2 для новых хранилищ.</summary>
        public const int DefaultIterations = 600000;

        // Границы для значения из файла: оно читается до проверки подлинности,
        // поэтому слишком большое число не должно «подвесить» программу.
        public const int MinIterations = 1000;
        public const int MaxIterations = 20000000;

        public const int MaxFileSize = 256 * 1024 * 1024;

        private static readonly byte[] Magic =
        {
            (byte)'K', (byte)'E', (byte)'Y', (byte)'B', (byte)'O', (byte)'X'
        };

        /// <summary>Получает ключ шифрования из мастер-пароля.</summary>
        public static byte[] DeriveKey(string password, byte[] salt, int iterations)
        {
            if (password == null) throw new ArgumentNullException("password");

            byte[] bytes = Encoding.UTF8.GetBytes(NormalizePassword(password));
            try
            {
                return Cng.Pbkdf2Sha512(bytes, salt, iterations, Cng.KeySize);
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

        /// <summary>Шифрует данные и собирает файл хранилища целиком.</summary>
        public static byte[] Seal(byte[] key, byte[] salt, int iterations, byte[] plaintext)
        {
            if (salt == null || salt.Length != SaltSize) throw new ArgumentException("Неверный размер соли.", "salt");
            if (iterations < MinIterations || iterations > MaxIterations) throw new ArgumentOutOfRangeException("iterations");

            byte[] nonce = Cng.RandomBytes(Cng.NonceSize);

            byte[] header = new byte[HeaderSize];
            Buffer.BlockCopy(Magic, 0, header, 0, Magic.Length);
            header[6] = (byte)FormatVersion;
            header[7] = 0;
            header[8] = KdfPbkdf2Sha512;
            header[9] = CipherAes256Gcm;
            header[10] = (byte)iterations;
            header[11] = (byte)(iterations >> 8);
            header[12] = (byte)(iterations >> 16);
            header[13] = (byte)(iterations >> 24);
            Buffer.BlockCopy(salt, 0, header, 14, SaltSize);
            Buffer.BlockCopy(nonce, 0, header, 14 + SaltSize, Cng.NonceSize);

            byte[] tag;
            byte[] ciphertext = Cng.AesGcmEncrypt(key, nonce, plaintext, header, out tag);

            byte[] file = new byte[HeaderSize + ciphertext.Length + Cng.TagSize];
            Buffer.BlockCopy(header, 0, file, 0, HeaderSize);
            Buffer.BlockCopy(ciphertext, 0, file, HeaderSize, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, file, HeaderSize + ciphertext.Length, Cng.TagSize);
            return file;
        }

        /// <summary>Разбирает и проверяет заголовок файла.</summary>
        public static VaultHeader ParseHeader(byte[] file)
        {
            if (file == null || file.Length < HeaderSize + Cng.TagSize) throw NotAVault();
            for (int i = 0; i < Magic.Length; i++)
            {
                if (file[i] != Magic[i]) throw NotAVault();
            }

            int version = file[6] | (file[7] << 8);
            if (version > FormatVersion)
            {
                throw new VaultException(VaultError.UnsupportedVersion,
                    "Хранилище создано более новой версией KeyBox. Обновите программу.");
            }
            if (version != FormatVersion) throw NotAVault();

            if (file[8] != KdfPbkdf2Sha512 || file[9] != CipherAes256Gcm)
            {
                throw new VaultException(VaultError.UnsupportedVersion,
                    "Хранилище зашифровано алгоритмом, который эта версия KeyBox не поддерживает.");
            }

            long iterations = (uint)(file[10] | (file[11] << 8) | (file[12] << 16) | (file[13] << 24));
            if (iterations < MinIterations || iterations > MaxIterations) throw NotAVault();

            var header = new VaultHeader();
            header.Iterations = (int)iterations;
            header.Salt = Slice(file, 14, SaltSize);
            header.Nonce = Slice(file, 14 + SaltSize, Cng.NonceSize);
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

            byte[] associatedData = Slice(file, 0, HeaderSize);
            byte[] ciphertext = Slice(file, HeaderSize, file.Length - HeaderSize - Cng.TagSize);
            byte[] tag = Slice(file, file.Length - Cng.TagSize, Cng.TagSize);

            byte[] plaintext;
            if (!Cng.AesGcmDecrypt(key, header.Nonce, ciphertext, associatedData, tag, out plaintext))
            {
                throw new VaultException(VaultError.WrongPassword,
                    "Неверный мастер-пароль или файл хранилища повреждён.");
            }
            return plaintext;
        }

        private static VaultException NotAVault()
        {
            return new VaultException(VaultError.BadFormat,
                "Файл не является хранилищем KeyBox или повреждён.");
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }
    }
}
