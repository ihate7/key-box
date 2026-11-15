using System;
using System.Globalization;
using System.Runtime.InteropServices;

namespace KeyBox
{
    /// <summary>Язык интерфейса программы.</summary>
    internal enum Language
    {
        Russian,
        English
    }

    /// <summary>
    /// Тексты интерфейса на двух языках. Отдельных файлов с переводами нет: русский и английский
    /// варианты строки стоят рядом, прямо в месте использования — L.T("Отмена", "Cancel").
    /// Так перевод невозможно забыть, а программа остаётся одним файлом.
    /// </summary>
    internal static class L
    {
        private const int LangRussian = 0x19;

        private static Language current = DetectSystemLanguage();

        /// <summary>Язык, на котором сейчас показываются все тексты.</summary>
        public static Language Current
        {
            get { return current; }
            set { current = value; }
        }

        public static bool IsEnglish
        {
            get { return current == Language.English; }
        }

        /// <summary>Строка на текущем языке.</summary>
        public static string T(string russian, string english)
        {
            return current == Language.English ? english : russian;
        }

        /// <summary>Строка на текущем языке с подстановкой значений, как в string.Format.</summary>
        public static string F(string russian, string english, params object[] arguments)
        {
            return string.Format(T(russian, english), arguments);
        }

        /// <summary>
        /// Число с существительным в нужной форме: «1 запись, 2 записи, 5 записей»
        /// или «1 entry, 2 entries».
        /// </summary>
        public static string Plural(int count, string one, string few, string many, string englishOne, string englishMany)
        {
            string word;
            if (current == Language.English)
            {
                word = Math.Abs(count) == 1 ? englishOne : englishMany;
            }
            else
            {
                int n = Math.Abs(count) % 100;
                int last = n % 10;
                if (n >= 11 && n <= 14) word = many;
                else if (last == 1) word = one;
                else if (last >= 2 && last <= 4) word = few;
                else word = many;
            }
            return count + " " + word;
        }

        /// <summary>Дата и время для показа пользователю.</summary>
        public static string FormatTime(DateTime local)
        {
            return local.ToString(current == Language.English ? "yyyy-MM-dd HH:mm" : "dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture);
        }

        /// <summary>Язык из настройки: "ru", "en" или что угодно другое — «как в системе».</summary>
        public static Language FromSetting(string code)
        {
            if (string.Equals(code, "ru", StringComparison.OrdinalIgnoreCase)) return Language.Russian;
            if (string.Equals(code, "en", StringComparison.OrdinalIgnoreCase)) return Language.English;
            return DetectSystemLanguage();
        }

        /// <summary>
        /// Язык «как в системе»: русский, если Windows на русском или в ней есть русская раскладка
        /// клавиатуры (Windows на другом языке, а человек читает по-русски), иначе английский.
        /// </summary>
        public static Language DetectSystemLanguage()
        {
            try
            {
                if (string.Equals(CultureInfo.CurrentUICulture.TwoLetterISOLanguageName, "ru", StringComparison.OrdinalIgnoreCase))
                {
                    return Language.Russian;
                }

                int count = GetKeyboardLayoutList(0, null);
                if (count > 0)
                {
                    var layouts = new IntPtr[count];
                    count = GetKeyboardLayoutList(layouts.Length, layouts);
                    for (int i = 0; i < count && i < layouts.Length; i++)
                    {
                        // Младшее слово — идентификатор языка, его младшие 10 бит — основной язык.
                        if (((int)(layouts[i].ToInt64() & 0x3FF)) == LangRussian) return Language.Russian;
                    }
                }
            }
            catch (DllNotFoundException) { }
            catch (EntryPointNotFoundException) { }
            return Language.English;
        }

        [DllImport("user32.dll")]
        private static extern int GetKeyboardLayoutList(int nBuff, [Out] IntPtr[] lpList);
    }
}
