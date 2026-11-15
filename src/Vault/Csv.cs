using System.Collections.Generic;
using System.Text;

namespace KeyBox.Vault
{
    /// <summary>
    /// Чтение и запись CSV по RFC 4180: поля в кавычках могут содержать запятые, кавычки
    /// (удвоенные) и переводы строк. При чтении разделитель определяется по первой строке —
    /// запятая, точка с запятой или табуляция.
    /// </summary>
    internal static class Csv
    {
        private const char ByteOrderMark = (char)0xFEFF;

        public static List<string[]> Parse(string text)
        {
            var rows = new List<string[]>();
            if (string.IsNullOrEmpty(text)) return rows;
            if (text[0] == ByteOrderMark) text = text.Substring(1);

            char separator = DetectSeparator(text);
            var row = new List<string>();
            var field = new StringBuilder();
            bool quoted = false;
            bool wasQuoted = false;

            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (quoted)
                {
                    if (c != '"')
                    {
                        field.Append(c);
                        i++;
                    }
                    else if (i + 1 < text.Length && text[i + 1] == '"')
                    {
                        field.Append('"'); // удвоенная кавычка внутри поля — одна кавычка
                        i += 2;
                    }
                    else
                    {
                        quoted = false;
                        i++;
                    }
                }
                else if (c == '"' && field.Length == 0 && !wasQuoted)
                {
                    quoted = true;
                    wasQuoted = true;
                    i++;
                }
                else if (c == separator)
                {
                    row.Add(field.ToString());
                    field.Length = 0;
                    wasQuoted = false;
                    i++;
                }
                else if (c == '\r' || c == '\n')
                {
                    if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n') i++;
                    i++;
                    row.Add(field.ToString());
                    field.Length = 0;
                    wasQuoted = false;
                    AddRow(rows, row);
                    row = new List<string>();
                }
                else
                {
                    field.Append(c);
                    i++;
                }
            }

            if (field.Length > 0 || wasQuoted || row.Count > 0)
            {
                row.Add(field.ToString());
                AddRow(rows, row);
            }
            return rows;
        }

        /// <summary>Записывает строки в CSV с запятой-разделителем и окончаниями строк CRLF.</summary>
        public static string Write(IEnumerable<string[]> rows)
        {
            var builder = new StringBuilder();
            foreach (string[] row in rows)
            {
                for (int i = 0; i < row.Length; i++)
                {
                    if (i > 0) builder.Append(',');
                    builder.Append(Escape(row[i]));
                }
                builder.Append("\r\n");
            }
            return builder.ToString();
        }

        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            bool needsQuotes = value.IndexOfAny(new[] { ',', ';', '"', '\r', '\n', '\t' }) >= 0 ||
                               value[0] == ' ' || value[value.Length - 1] == ' ';
            return needsQuotes ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
        }

        /// <summary>Пустые строки файла (в том числе в конце) пропускаются.</summary>
        private static void AddRow(List<string[]> rows, List<string> row)
        {
            if (row.Count == 1 && row[0].Length == 0) return;
            rows.Add(row.ToArray());
        }

        private static char DetectSeparator(string text)
        {
            int commas = 0;
            int semicolons = 0;
            int tabs = 0;
            bool quoted = false;
            foreach (char c in text)
            {
                if (c == '"') quoted = !quoted;
                else if (!quoted && (c == '\r' || c == '\n')) break;
                else if (!quoted && c == ',') commas++;
                else if (!quoted && c == ';') semicolons++;
                else if (!quoted && c == '\t') tabs++;
            }
            if (semicolons > commas && semicolons >= tabs) return ';';
            if (tabs > commas && tabs > semicolons) return '\t';
            return ',';
        }
    }
}
