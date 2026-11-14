using System;
using System.Security.Cryptography;

namespace KeyBox.Crypto
{
    /// <summary>Генератор случайных паролей на системном криптографическом ГСЧ.</summary>
    internal static class PasswordGenerator
    {
        public const int DefaultLength = 20;

        // Без похожих друг на друга символов (O/0, I/l/1), чтобы пароль можно было
        // при необходимости перепечатать вручную.
        private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        private const string Lower = "abcdefghijkmnpqrstuvwxyz";
        private const string Digits = "23456789";
        private const string Symbols = "!@#$%^&*-_=+?";

        public static string Generate(int length)
        {
            if (length < 4) throw new ArgumentOutOfRangeException("length");

            string all = Upper + Lower + Digits + Symbols;
            char[] chars = new char[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                // По одному символу каждого класса, остальные — из общего алфавита.
                chars[0] = Pick(rng, Upper);
                chars[1] = Pick(rng, Lower);
                chars[2] = Pick(rng, Digits);
                chars[3] = Pick(rng, Symbols);
                for (int i = 4; i < length; i++)
                {
                    chars[i] = Pick(rng, all);
                }

                // Перемешивание Фишера — Йетса, чтобы обязательные символы не стояли в начале.
                for (int i = length - 1; i > 0; i--)
                {
                    int j = Next(rng, i + 1);
                    char tmp = chars[i];
                    chars[i] = chars[j];
                    chars[j] = tmp;
                }
            }

            string result = new string(chars);
            Array.Clear(chars, 0, chars.Length);
            return result;
        }

        private static char Pick(RandomNumberGenerator rng, string alphabet)
        {
            return alphabet[Next(rng, alphabet.Length)];
        }

        /// <summary>Равномерное случайное число в [0, exclusiveMax) без смещения от деления по модулю.</summary>
        private static int Next(RandomNumberGenerator rng, int exclusiveMax)
        {
            ulong range = (ulong)exclusiveMax;
            ulong bound = (0x100000000UL / range) * range;
            byte[] buffer = new byte[4];
            while (true)
            {
                rng.GetBytes(buffer);
                ulong value = BitConverter.ToUInt32(buffer, 0);
                if (value < bound) return (int)(value % range);
            }
        }
    }
}
