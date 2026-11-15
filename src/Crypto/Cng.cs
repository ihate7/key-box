using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace KeyBox.Crypto
{
    /// <summary>
    /// Криптография на системных примитивах Windows (CNG, bcrypt.dll):
    /// PBKDF2-HMAC-SHA512 для получения ключа из пароля и AES-256-GCM для шифрования.
    /// Собственных реализаций алгоритмов здесь нет — только вызовы ОС.
    /// </summary>
    internal static class Cng
    {
        /// <summary>Размер ключа AES-256, байт.</summary>
        public const int KeySize = 32;

        /// <summary>Размер nonce для GCM, байт (96 бит — рекомендуемый стандартом).</summary>
        public const int NonceSize = 12;

        /// <summary>Размер тега аутентификации GCM, байт.</summary>
        public const int TagSize = 16;

        private const uint BCRYPT_ALG_HANDLE_HMAC_FLAG = 0x00000008;
        private const int STATUS_AUTH_TAG_MISMATCH = unchecked((int)0xC000A002);

        /// <summary>Криптографически стойкие случайные байты.</summary>
        public static byte[] RandomBytes(int count)
        {
            byte[] bytes = new byte[count];
            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(bytes);
            }
            return bytes;
        }

        /// <summary>PBKDF2-HMAC-SHA512 (RFC 8018).</summary>
        public static byte[] Pbkdf2Sha512(byte[] password, byte[] salt, int iterations, int outputLength)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (salt == null) throw new ArgumentNullException("salt");
            if (iterations < 1) throw new ArgumentOutOfRangeException("iterations");
            if (outputLength < 1) throw new ArgumentOutOfRangeException("outputLength");

            IntPtr algorithm = IntPtr.Zero;
            try
            {
                Check("BCryptOpenAlgorithmProvider",
                    BCryptOpenAlgorithmProvider(out algorithm, "SHA512", null, BCRYPT_ALG_HANDLE_HMAC_FLAG));

                byte[] derived = new byte[outputLength];
                Check("BCryptDeriveKeyPBKDF2",
                    BCryptDeriveKeyPBKDF2(algorithm, password, password.Length, salt, salt.Length,
                        (ulong)iterations, derived, derived.Length, 0));
                return derived;
            }
            finally
            {
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            }
        }

        /// <summary>
        /// Шифрует AES-256-GCM. Возвращает шифртекст той же длины, что и открытый текст;
        /// тег аутентификации возвращается отдельно.
        /// </summary>
        public static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, out byte[] tag)
        {
            if (plaintext == null) throw new ArgumentNullException("plaintext");

            tag = new byte[TagSize];
            byte[] output;
            int status = AesGcm(true, key, nonce, plaintext, associatedData, tag, out output);
            Check("BCryptEncrypt", status);
            return output;
        }

        /// <summary>
        /// Расшифровывает AES-256-GCM. Возвращает false, если тег не сошёлся:
        /// неверный ключ либо данные (или заголовок) были изменены.
        /// </summary>
        public static bool AesGcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData, byte[] tag, out byte[] plaintext)
        {
            if (ciphertext == null) throw new ArgumentNullException("ciphertext");
            if (tag == null) throw new ArgumentNullException("tag");
            if (tag.Length != TagSize) throw new ArgumentException("Invalid tag size.", "tag");

            byte[] output;
            int status = AesGcm(false, key, nonce, ciphertext, associatedData, (byte[])tag.Clone(), out output);
            if (status == STATUS_AUTH_TAG_MISMATCH)
            {
                // Содержимое буфера при несошедшемся теге использовать нельзя.
                Array.Clear(output, 0, output.Length);
                plaintext = null;
                return false;
            }
            Check("BCryptDecrypt", status);
            plaintext = output;
            return true;
        }

        private static int AesGcm(bool encrypt, byte[] key, byte[] nonce, byte[] input, byte[] associatedData, byte[] tag, out byte[] output)
        {
            if (key == null) throw new ArgumentNullException("key");
            if (nonce == null) throw new ArgumentNullException("nonce");
            if (key.Length != KeySize) throw new ArgumentException("Invalid key size.", "key");
            if (nonce.Length != NonceSize) throw new ArgumentException("Invalid nonce size.", "nonce");

            IntPtr algorithm = IntPtr.Zero;
            IntPtr keyHandle = IntPtr.Zero;
            GCHandle pinnedNonce = default(GCHandle);
            GCHandle pinnedTag = default(GCHandle);
            GCHandle pinnedData = default(GCHandle);
            try
            {
                Check("BCryptOpenAlgorithmProvider",
                    BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0));

                byte[] mode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
                Check("BCryptSetProperty",
                    BCryptSetProperty(algorithm, "ChainingMode", mode, mode.Length, 0));

                Check("BCryptGenerateSymmetricKey",
                    BCryptGenerateSymmetricKey(algorithm, out keyHandle, IntPtr.Zero, 0, key, key.Length, 0));

                pinnedNonce = GCHandle.Alloc(nonce, GCHandleType.Pinned);
                pinnedTag = GCHandle.Alloc(tag, GCHandleType.Pinned);

                var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
                info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
                info.dwInfoVersion = 1;
                info.pbNonce = pinnedNonce.AddrOfPinnedObject();
                info.cbNonce = nonce.Length;
                info.pbTag = pinnedTag.AddrOfPinnedObject();
                info.cbTag = tag.Length;
                if (associatedData != null && associatedData.Length > 0)
                {
                    pinnedData = GCHandle.Alloc(associatedData, GCHandleType.Pinned);
                    info.pbAuthData = pinnedData.AddrOfPinnedObject();
                    info.cbAuthData = associatedData.Length;
                }

                output = new byte[input.Length];
                int written;
                int status = encrypt
                    ? BCryptEncrypt(keyHandle, input, input.Length, ref info, null, 0, output, output.Length, out written, 0)
                    : BCryptDecrypt(keyHandle, input, input.Length, ref info, null, 0, output, output.Length, out written, 0);

                if (status == 0 && written != input.Length)
                {
                    throw new CryptographicException(L.T("AES-GCM вернул неожиданный размер данных.", "AES-GCM returned an unexpected data size."));
                }
                return status;
            }
            finally
            {
                if (pinnedData.IsAllocated) pinnedData.Free();
                if (pinnedTag.IsAllocated) pinnedTag.Free();
                if (pinnedNonce.IsAllocated) pinnedNonce.Free();
                if (keyHandle != IntPtr.Zero) BCryptDestroyKey(keyHandle);
                if (algorithm != IntPtr.Zero) BCryptCloseAlgorithmProvider(algorithm, 0);
            }
        }

        private static void Check(string function, int status)
        {
            if (status != 0)
            {
                throw new CryptographicException(
                    L.F("{0}: ошибка криптографии Windows 0x{1:X8}.", "{0}: Windows cryptography error 0x{1:X8}.", function, status));
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
        {
            public int cbSize;
            public int dwInfoVersion;
            public IntPtr pbNonce;
            public int cbNonce;
            public IntPtr pbAuthData;
            public int cbAuthData;
            public IntPtr pbTag;
            public int cbTag;
            public IntPtr pbMacContext;
            public int cbMacContext;
            public int cbAAD;
            public long cbData;
            public int dwFlags;
        }

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

        [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDestroyKey(IntPtr hKey);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

        [DllImport("bcrypt.dll")]
        private static extern int BCryptDeriveKeyPBKDF2(IntPtr hPrf, byte[] pbPassword, int cbPassword, byte[] pbSalt, int cbSalt, ulong cIterations, byte[] pbDerivedKey, int cbDerivedKey, uint dwFlags);
    }
}
