using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Cryptography;

namespace KeyBox.Crypto
{
    /// <summary>Ключ одноразовых кодов и его параметры.</summary>
    internal sealed class TotpKey
    {
        public byte[] Secret;
        public int Digits = Totp.DefaultDigits;
        public int Period = Totp.DefaultPeriod;

        /// <summary>SHA1, SHA256 или SHA512.</summary>
        public string Algorithm = "SHA1";
    }

    /// <summary>
    /// Одноразовые коды по времени (TOTP, RFC 6238) — те самые шесть цифр, которые показывает
    /// приложение-аутентификатор. Ключ задаётся строкой Base32 или ссылкой otpauth://totp/…
    /// </summary>
    internal static class Totp
    {
        public const int DefaultDigits = 6;
        public const int DefaultPeriod = 30;

        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Разбирает ключ, введённый пользователем: секрет в Base32 (пробелы, дефисы и регистр
        /// не важны) или ссылку otpauth://totp/…?secret=… Возвращает null, если ключ не распознан.
        /// </summary>
        public static TotpKey Parse(string text)
        {
            string value = (text ?? "").Trim();
            if (value.Length == 0) return null;

            if (value.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            {
                return ParseUri(value);
            }

            byte[] secret = Base32Decode(value);
            if (secret == null || secret.Length < 5) return null;
            var key = new TotpKey();
            key.Secret = secret;
            return key;
        }

        /// <summary>Код, действующий в указанный момент.</summary>
        public static string Code(TotpKey key, DateTime utcNow)
        {
            if (key == null) throw new ArgumentNullException("key");

            long counter = Counter(key, utcNow);
            byte[] message = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                message[i] = (byte)(counter & 0xFF);
                counter >>= 8;
            }

            byte[] hash;
            using (HMAC hmac = CreateHmac(key.Algorithm, key.Secret))
            {
                hash = hmac.ComputeHash(message);
            }

            // «Динамическое усечение» из RFC 4226: четыре байта со смещения, заданного последним полубайтом.
            int offset = hash[hash.Length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
            Array.Clear(hash, 0, hash.Length);

            int modulus = 1;
            for (int i = 0; i < key.Digits; i++) modulus *= 10;
            return (binary % modulus).ToString(CultureInfo.InvariantCulture).PadLeft(key.Digits, '0');
        }

        /// <summary>Сколько секунд код ещё действует.</summary>
        public static int SecondsLeft(TotpKey key, DateTime utcNow)
        {
            long seconds = UnixSeconds(utcNow);
            return key.Period - (int)(seconds % key.Period);
        }

        /// <summary>Код, разбитый на группы для чтения: «123 456».</summary>
        public static string Readable(string code)
        {
            if (string.IsNullOrEmpty(code) || code.Length < 6) return code ?? "";
            int half = code.Length / 2;
            return code.Substring(0, half) + " " + code.Substring(half);
        }

        /// <summary>Декодирует Base32 (RFC 4648). Возвращает null, если в строке есть посторонние символы.</summary>
        public static byte[] Base32Decode(string text)
        {
            if (text == null) return null;

            var output = new List<byte>();
            int buffer = 0;
            int bits = 0;
            bool padding = false;
            foreach (char raw in text)
            {
                if (raw == ' ' || raw == '-' || raw == '\t' || raw == '\r' || raw == '\n') continue;
                if (raw == '=')
                {
                    padding = true;
                    continue;
                }
                if (padding) return null; // после заполнителя «=» данных быть не может

                int index = Base32Alphabet.IndexOf(char.ToUpperInvariant(raw));
                if (index < 0) return null;

                buffer = (buffer << 5) | index;
                bits += 5;
                if (bits >= 8)
                {
                    bits -= 8;
                    output.Add((byte)((buffer >> bits) & 0xFF));
                    buffer &= (1 << bits) - 1;
                }
            }
            return output.ToArray();
        }

        private static TotpKey ParseUri(string value)
        {
            Uri uri;
            if (!Uri.TryCreate(value, UriKind.Absolute, out uri)) return null;
            if (!string.Equals(uri.Host, "totp", StringComparison.OrdinalIgnoreCase)) return null; // счётчиковые коды (hotp) не поддерживаются

            var key = new TotpKey();
            string query = uri.Query.TrimStart('?');
            foreach (string pair in query.Split(new[] { '&' }, StringSplitOptions.RemoveEmptyEntries))
            {
                int equals = pair.IndexOf('=');
                if (equals <= 0) continue;
                string name = pair.Substring(0, equals).ToLowerInvariant();
                string parameter;
                try
                {
                    parameter = Uri.UnescapeDataString(pair.Substring(equals + 1).Replace('+', ' '));
                }
                catch (UriFormatException)
                {
                    return null;
                }

                int number;
                if (name == "secret")
                {
                    key.Secret = Base32Decode(parameter);
                }
                else if (name == "digits")
                {
                    if (!int.TryParse(parameter, NumberStyles.None, CultureInfo.InvariantCulture, out number) || number < 6 || number > 8) return null;
                    key.Digits = number;
                }
                else if (name == "period")
                {
                    if (!int.TryParse(parameter, NumberStyles.None, CultureInfo.InvariantCulture, out number) || number < 5 || number > 300) return null;
                    key.Period = number;
                }
                else if (name == "algorithm")
                {
                    string algorithm = parameter.ToUpperInvariant().Replace("-", "");
                    if (algorithm != "SHA1" && algorithm != "SHA256" && algorithm != "SHA512") return null;
                    key.Algorithm = algorithm;
                }
            }
            return key.Secret == null || key.Secret.Length == 0 ? null : key;
        }

        private static long Counter(TotpKey key, DateTime utcNow)
        {
            return UnixSeconds(utcNow) / key.Period;
        }

        private static long UnixSeconds(DateTime utcNow)
        {
            long seconds = (long)Math.Floor((utcNow.ToUniversalTime() - UnixEpoch).TotalSeconds);
            return seconds < 0 ? 0 : seconds;
        }

        private static HMAC CreateHmac(string algorithm, byte[] secret)
        {
            if (algorithm == "SHA256") return new HMACSHA256(secret);
            if (algorithm == "SHA512") return new HMACSHA512(secret);
            return new HMACSHA1(secret);
        }
    }
}
