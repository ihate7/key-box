using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace KeyBox.Crypto
{
    /// <summary>Генератор случайных паролей на системном криптографическом ГСЧ.</summary>
    internal static class PasswordGenerator
    {
        public const int DefaultLength = 20;

        // Наборы без похожих друг на друга символов (O/0, I/l/1): такой пароль проще
        // при необходимости перепечатать вручную.
        private const string UpperClear = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        private const string LowerClear = "abcdefghijkmnpqrstuvwxyz";
        private const string DigitsClear = "23456789";

        private const string UpperAll = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string LowerAll = "abcdefghijklmnopqrstuvwxyz";
        private const string DigitsAll = "0123456789";

        private const string Symbols = "!@#$%^&*-_=+?";

        /// <summary>Пароль из букв обоих регистров, цифр и знаков, без похожих символов.</summary>
        public static string Generate(int length)
        {
            return Generate(length, true, true, true, true, true);
        }

        /// <summary>
        /// Пароль заданной длины из выбранных классов символов. Каждый выбранный класс
        /// обязательно представлен хотя бы одним символом.
        /// </summary>
        public static string Generate(int length, bool upper, bool lower, bool digits, bool symbols, bool noLookAlikes)
        {
            var classes = new List<string>();
            if (upper) classes.Add(noLookAlikes ? UpperClear : UpperAll);
            if (lower) classes.Add(noLookAlikes ? LowerClear : LowerAll);
            if (digits) classes.Add(noLookAlikes ? DigitsClear : DigitsAll);
            if (symbols) classes.Add(Symbols);
            if (classes.Count == 0) throw new ArgumentException("At least one character class is required.");
            if (length < classes.Count) throw new ArgumentOutOfRangeException("length");

            string all = string.Concat(classes.ToArray());
            char[] chars = new char[length];
            using (var rng = new RNGCryptoServiceProvider())
            {
                // По одному символу каждого класса, остальные — из общего алфавита.
                for (int i = 0; i < classes.Count; i++)
                {
                    chars[i] = Pick(rng, classes[i]);
                }
                for (int i = classes.Count; i < length; i++)
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
