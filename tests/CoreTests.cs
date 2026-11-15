using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using KeyBox.Crypto;
using KeyBox.Vault;

namespace KeyBox.Tests
{
    /// <summary>
    /// Тесты ядра (шифрование, формат файла, модель данных) без интерфейса.
    /// Запуск: tests\run-tests.cmd. Код возврата 0 — всё прошло.
    /// </summary>
    internal static class CoreTests
    {
        // Общие с tests/interop.js значения. В interop.js буква «й» в пароле записана
        // двумя символами (и + кратка), здесь — одним: так проверяется приведение к NFC.
        private static readonly string Key = char.ConvertFromUtf32(0x1F511);      // эмодзи «ключ»
        private static readonly string InteropPassword = "Пароль-" + (char)0x0439 + "-" + Key;
        private static readonly string InteropSecret = "p@ss \"quoted\" \\ слово " + Key + " <tag> / \t";

        private const int FastIterations = 1000;
        private const string Password = "correct horse battery staple";

        private static int passed;
        private static int failed;
        private static string workDir;

        private static int Main(string[] args)
        {
            Console.OutputEncoding = new UTF8Encoding(false);

            // Тесты сверяют тексты сообщений, поэтому язык задаётся явно, а не берётся из системы.
            L.SystemLanguageOverride = Language.Russian;
            L.Current = Language.Russian;

            workDir = args.Length > 0
                ? Path.GetFullPath(args[0])
                : Path.Combine(Path.GetTempPath(), "keybox-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(workDir);

            Run("pbkdf2-sha512: known answers", Pbkdf2KnownAnswers);
            Run("pbkdf2-sha512: matches .NET implementation", Pbkdf2MatchesManaged);
            Run("aes-256-gcm: NIST known answers", AesGcmKnownAnswers);
            Run("aes-256-gcm: round trip, all sizes", AesGcmRoundTrip);
            Run("aes-256-gcm: detects any modification", AesGcmDetectsTampering);
            Run("blake2b: known answers", Blake2bKnownAnswers);
            Run("argon2id: RFC 9106 and cross-checked answers", Argon2idKnownAnswers);
            Run("argon2id: parameters matter, bad ones are refused", Argon2idProperties);
            Run("format: layout and round trip", FormatRoundTrip);
            Run("format: every flipped byte is rejected", FormatRejectsEveryFlippedByte);
            Run("format: truncated and foreign files are rejected", FormatRejectsTruncated);
            Run("format: header limits are enforced before the KDF runs", FormatHeaderLimits);
            Run("format: fresh nonce on every save", FormatFreshNonce);
            Run("format 2: layout, round trip, tampering, limits", FormatVersion2);
            Run("password: unicode and NFC normalisation", PasswordNormalisation);
            Run("session: create, save, reopen", SessionCreateSaveOpen);
            Run("session: wrong password", SessionWrongPassword);
            Run("session: backup keeps the previous version", SessionBackup);
            Run("session: the same on file systems without atomic replace", SessionBackupSimpleReplace);
            Run("session: change master password", SessionChangePassword);
            Run("session: no plaintext or leftovers on disk", SessionNoPlaintextOnDisk);
            Run("session: disposed session cannot save", SessionDisposed);
            Run("session: new vaults use Argon2id", SessionArgon2);
            Run("session: key file as a second factor", SessionKeyFile);
            Run("model: groups", ModelGroups);
            Run("model: entries", ModelEntries);
            Run("model: moving entries between groups", ModelMove);
            Run("model: deleting a group keeps its entries", ModelDeleteGroup);
            Run("model: filter and search", ModelQuery);
            Run("nested groups: create, paths, tree order", NestedGroups);
            Run("nested groups: move and rename, forbidden moves", NestedGroupsMove);
            Run("nested groups: depth limit", NestedGroupsDepthLimit);
            Run("nested groups: deleting a branch moves entries one level up", NestedGroupsDelete);
            Run("nested groups: filter and search", NestedGroupsQuery);
            Run("nested groups: file versions 1 and 2, broken links", NestedGroupsJson);
            Run("totp: RFC 6238 known answers", TotpKnownAnswers);
            Run("totp: key formats", TotpKeyFormats);
            Run("model: website and one-time code key", ModelWebsiteAndTotp);
            Run("model: password history", ModelPasswordHistory);
            Run("model: trash", ModelTrash);
            Run("model: settings", ModelSettings);
            Run("model: structure version 3 only when it is needed", ModelVersion3);
            Run("merge: additions and edits from both copies", MergeAdditionsAndEdits);
            Run("merge: deletions, the trash and resurrection", MergeDeletions);
            Run("merge: groups renamed, moved, deleted, duplicated", MergeGroups);
            Run("merge: settings and the order of merging", MergeSettingsAndSymmetry);
            Run("shared file: two open copies do not overwrite each other", SharedFileMerge);
            Run("shared file: a check picks up changes and writes back what is missing", SharedFileReload);
            Run("shared file: password changed elsewhere, newer version, damaged file", SharedFileConflict);
            Run("csv: quotes, separators, line breaks", CsvParsing);
            Run("import: files of browsers and password managers", ImportFormats);
            Run("import: groups, one-time codes, odd rows", ImportIntoVault);
            Run("export: csv that reads back without losses", ExportRoundTrip);
            Run("json: unicode and special characters", JsonSpecialCharacters);
            Run("json: damaged and foreign data", JsonNormalisation);
            Run("localisation: plural forms, dates, language choice", LocalisationBasics);
            Run("localisation: every text in the sources has both languages", LocalisationCoverage);
            Run("generator: alphabet, classes, uniqueness", GeneratorProperties);
            Run("generator: options from the settings", GeneratorOptions);
            Run("large vault: 5000 entries", LargeVault);
            Run("interop: files shared with the Node.js implementation", Interop);
            Run("kdf: timing with default parameters", KdfTiming);

            Console.WriteLine();
            Console.WriteLine("{0} passed, {1} failed", passed, failed);
            return failed == 0 ? 0 : 1;
        }

        // ---------- Криптография ----------

        private static void Pbkdf2KnownAnswers()
        {
            byte[] password = Ascii("password");
            byte[] salt = Ascii("salt");

            Equal("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce",
                Cng.Pbkdf2Sha512(password, salt, 1, 64));
            Equal("e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e",
                Cng.Pbkdf2Sha512(password, salt, 2, 64));
            Equal("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5",
                Cng.Pbkdf2Sha512(password, salt, 4096, 64));
            Equal("8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8",
                Cng.Pbkdf2Sha512(Ascii("passwordPASSWORDpassword"), Ascii("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 64));

            // Короткий вывод — начало длинного.
            Equal("867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252",
                Cng.Pbkdf2Sha512(password, salt, 1, 32));
        }

        private static void Pbkdf2MatchesManaged()
        {
            var random = new Random(20261114);
            for (int i = 0; i < 25; i++)
            {
                byte[] password = new byte[1 + random.Next(150)];
                byte[] salt = new byte[8 + random.Next(56)];
                random.NextBytes(password);
                random.NextBytes(salt);
                int iterations = 1 + random.Next(400);
                int length = 1 + random.Next(130);

                byte[] expected;
                using (var managed = new Rfc2898DeriveBytes(password, salt, iterations, HashAlgorithmName.SHA512))
                {
                    expected = managed.GetBytes(length);
                }
                Equal(expected, Cng.Pbkdf2Sha512(password, salt, iterations, length));
            }
        }

        private static void AesGcmKnownAnswers()
        {
            byte[] zeroKey = new byte[32];
            byte[] zeroNonce = new byte[12];
            byte[] tag;

            // NIST GCM, Test Case 13: пустой открытый текст.
            byte[] c13 = Cng.AesGcmEncrypt(zeroKey, zeroNonce, new byte[0], null, out tag);
            Equal("", c13);
            Equal("530f8afbc74536b9a963b4f1c4cb738b", tag);

            // Test Case 14.
            byte[] c14 = Cng.AesGcmEncrypt(zeroKey, zeroNonce, new byte[16], null, out tag);
            Equal("cea7403d4d606b6e074ec5d3baf39d18", c14);
            Equal("d0d1c8a799996bf0265b98b5d48ab919", tag);

            // Test Case 16: с дополнительными аутентифицируемыми данными.
            byte[] key = Hex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
            byte[] nonce = Hex("cafebabefacedbaddecaf888");
            byte[] plain = Hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
            byte[] aad = Hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
            byte[] c16 = Cng.AesGcmEncrypt(key, nonce, plain, aad, out tag);
            Equal("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662", c16);
            Equal("76fc6ece0f4e1768cddf8853bb2d551b", tag);

            byte[] back;
            Check(Cng.AesGcmDecrypt(key, nonce, c16, aad, tag, out back), "decrypt of test case 16");
            Equal(plain, back);
        }

        private static void AesGcmRoundTrip()
        {
            var random = new Random(7);
            int[] sizes = { 0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 1000, 4096, 65537, 1000000 };
            foreach (int size in sizes)
            {
                byte[] key = Cng.RandomBytes(32);
                byte[] nonce = Cng.RandomBytes(12);
                byte[] plain = new byte[size];
                random.NextBytes(plain);
                byte[] aad = new byte[random.Next(100)];
                random.NextBytes(aad);

                byte[] tag;
                byte[] cipher = Cng.AesGcmEncrypt(key, nonce, plain, aad, out tag);
                Check(cipher.Length == size, "ciphertext length for size " + size);
                Check(tag.Length == 16, "tag length");
                if (size >= 16) Check(!SameBytes(cipher, plain), "ciphertext differs from plaintext");

                byte[] back;
                Check(Cng.AesGcmDecrypt(key, nonce, cipher, aad, tag, out back), "decrypt for size " + size);
                Equal(plain, back);
            }
        }

        private static void AesGcmDetectsTampering()
        {
            byte[] key = Cng.RandomBytes(32);
            byte[] nonce = Cng.RandomBytes(12);
            byte[] plain = Encoding.UTF8.GetBytes("логин и пароль, которые нельзя подменить");
            byte[] aad = Ascii("KEYBOX header");
            byte[] tag;
            byte[] cipher = Cng.AesGcmEncrypt(key, nonce, plain, aad, out tag);

            byte[] back;
            Check(Cng.AesGcmDecrypt(key, nonce, cipher, aad, tag, out back), "untouched data decrypts");

            Check(!DecryptsWithFlippedBit(key, nonce, cipher, aad, tag, cipher), "modified ciphertext");
            Check(!DecryptsWithFlippedBit(key, nonce, cipher, aad, tag, tag), "modified tag");
            Check(!DecryptsWithFlippedBit(key, nonce, cipher, aad, tag, aad), "modified associated data");
            Check(!DecryptsWithFlippedBit(key, nonce, cipher, aad, tag, nonce), "modified nonce");
            Check(!DecryptsWithFlippedBit(key, nonce, cipher, aad, tag, key), "modified key");

            Check(!Cng.AesGcmDecrypt(key, nonce, cipher, null, tag, out back), "missing associated data");
            Check(back == null, "no plaintext is returned on failure");
        }

        /// <summary>Переворачивает по очереди каждый бит в target; true, если хоть раз расшифровалось.</summary>
        private static bool DecryptsWithFlippedBit(byte[] key, byte[] nonce, byte[] cipher, byte[] aad, byte[] tag, byte[] target)
        {
            for (int i = 0; i < target.Length; i++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    target[i] ^= (byte)(1 << bit);
                    byte[] back;
                    bool ok = Cng.AesGcmDecrypt(key, nonce, cipher, aad, tag, out back);
                    target[i] ^= (byte)(1 << bit);
                    if (ok) return true;
                }
            }
            return false;
        }

        // ---------- Формат файла ----------

        private static void FormatRoundTrip()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] key = VaultFormat.DeriveKey(Password, salt, FastIterations);
            byte[] plain = Encoding.UTF8.GetBytes("{\"version\":1}");

            byte[] file = VaultFormat.Seal(key, salt, FastIterations, plain);
            Check(file.Length == 58 + plain.Length + 16, "file length");
            Check(Encoding.ASCII.GetString(file, 0, 6) == "KEYBOX", "signature");
            Check(file[6] == 1 && file[7] == 0, "format version");
            Check(file[8] == 1 && file[9] == 1, "algorithm ids");
            Check(BitConverter.ToInt32(file, 10) == FastIterations, "iterations field");
            Equal(salt, Slice(file, 14, 32));

            VaultHeader header = VaultFormat.ParseHeader(file);
            Check(header.Iterations == FastIterations, "parsed iterations");
            Equal(salt, header.Salt);
            Equal(Slice(file, 46, 12), header.Nonce);

            Equal(plain, VaultFormat.Open(key, file));

            // Открытого текста в файле нет.
            Check(IndexOf(file, plain) < 0, "plaintext must not appear in the file");
        }

        private static void FormatRejectsEveryFlippedByte()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] key = VaultFormat.DeriveKey(Password, salt, FastIterations);
            byte[] file = VaultFormat.Seal(key, salt, FastIterations, Encoding.UTF8.GetBytes("{\"version\":1,\"groups\":[],\"entries\":[]}"));

            for (int i = 0; i < file.Length; i++)
            {
                for (int bit = 0; bit < 8; bit++)
                {
                    byte[] damaged = (byte[])file.Clone();
                    damaged[i] ^= (byte)(1 << bit);
                    try
                    {
                        VaultFormat.Open(key, damaged);
                    }
                    catch (VaultException)
                    {
                        continue;
                    }
                    throw new Exception(string.Format("modified file was accepted (byte {0}, bit {1})", i, bit));
                }
            }
        }

        private static void FormatRejectsTruncated()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] key = VaultFormat.DeriveKey(Password, salt, FastIterations);
            byte[] file = VaultFormat.Seal(key, salt, FastIterations, Encoding.UTF8.GetBytes("{\"version\":1}"));

            for (int length = 0; length < file.Length; length++)
            {
                byte[] part = Slice(file, 0, length);
                try
                {
                    VaultFormat.Open(key, part);
                }
                catch (VaultException)
                {
                    continue;
                }
                throw new Exception("truncated file was accepted, length " + length);
            }

            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(null); });
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(new byte[0]); });
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(Ascii(new string('x', 500))); });
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(Cng.RandomBytes(4096)); });

            // Лишние байты в конце тоже ломают проверку подлинности.
            byte[] longer = new byte[file.Length + 1];
            Buffer.BlockCopy(file, 0, longer, 0, file.Length);
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultFormat.Open(key, longer); });
        }

        private static void FormatHeaderLimits()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] key = VaultFormat.DeriveKey(Password, salt, FastIterations);
            byte[] file = VaultFormat.Seal(key, salt, FastIterations, Encoding.UTF8.GetBytes("{}"));

            // Число итераций читается до проверки подлинности: огромное значение не должно дойти до KDF.
            byte[] huge = (byte[])file.Clone();
            huge[10] = 0xFF; huge[11] = 0xFF; huge[12] = 0xFF; huge[13] = 0xFF;
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(huge); });

            byte[] tooMany = (byte[])file.Clone();
            WriteInt32(tooMany, 10, VaultFormat.MaxIterations + 1);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(tooMany); });

            byte[] tooFew = (byte[])file.Clone();
            WriteInt32(tooFew, 10, VaultFormat.MinIterations - 1);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(tooFew); });

            byte[] newer = (byte[])file.Clone();
            newer[6] = 3;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(newer); });

            byte[] otherCipher = (byte[])file.Clone();
            otherCipher[9] = 2;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(otherCipher); });

            byte[] otherKdf = (byte[])file.Clone();
            otherKdf[8] = 2;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(otherKdf); });

            Check(VaultFormat.DefaultIterations >= 210000, "default iterations are not below the OWASP minimum for PBKDF2-HMAC-SHA512");
        }

        private static void FormatFreshNonce()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] key = VaultFormat.DeriveKey(Password, salt, FastIterations);
            byte[] plain = Encoding.UTF8.GetBytes("{\"version\":1}");

            var nonces = new HashSet<string>();
            for (int i = 0; i < 200; i++)
            {
                byte[] file = VaultFormat.Seal(key, salt, FastIterations, plain);
                Check(nonces.Add(ToHex(Slice(file, 46, 12))), "nonce must not repeat");
            }
        }

        private static void PasswordNormalisation()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);

            // «й» одним символом и двумя (и + кратка) — один и тот же пароль.
            string composed = "па" + (char)0x0439 + "роль";
            string decomposed = "па" + (char)0x0438 + (char)0x0306 + "роль";
            Check(composed != decomposed, "test strings differ");
            Equal(VaultFormat.DeriveKey(composed, salt, FastIterations), VaultFormat.DeriveKey(decomposed, salt, FastIterations));

            // Регистр, пробелы и соль значимы.
            NotEqual(VaultFormat.DeriveKey("Пароль", salt, FastIterations), VaultFormat.DeriveKey("пароль", salt, FastIterations));
            NotEqual(VaultFormat.DeriveKey("пароль", salt, FastIterations), VaultFormat.DeriveKey("пароль ", salt, FastIterations));
            NotEqual(VaultFormat.DeriveKey("пароль", salt, FastIterations), VaultFormat.DeriveKey("пароль", Cng.RandomBytes(32), FastIterations));
            NotEqual(VaultFormat.DeriveKey("пароль", salt, FastIterations), VaultFormat.DeriveKey("пароль", salt, FastIterations + 1));

            // Ключ совпадает с независимым вычислением: PBKDF2 от UTF-8.
            byte[] expected;
            using (var managed = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes("пароль " + Key), salt, FastIterations, HashAlgorithmName.SHA512))
            {
                expected = managed.GetBytes(32);
            }
            Equal(expected, VaultFormat.DeriveKey("пароль " + Key, salt, FastIterations));
        }

        // ---------- Сессия и файлы ----------

        private static void SessionCreateSaveOpen()
        {
            string path = NewVaultPath("session");
            string groupId;
            using (VaultSession session = VaultSession.Create(path, Password, FastIterations))
            {
                Check(File.Exists(path), "file is written on creation");
                Check(session.Data.Groups.Count == 0 && session.Data.Entries.Count == 0, "new vault is empty");

                Group group = session.Data.AddGroup("Работа");
                groupId = group.Id;
                session.Data.AddEntry(group.Id, "ivan", "s3cret", "Почта");
                session.Data.AddEntry(null, "root", "toor", "Сервер");
                session.Save();
            }

            using (VaultSession session = VaultSession.Open(path, Password))
            {
                Check(session.Iterations == FastIterations, "iterations survive");
                Check(session.Data.Groups.Count == 1, "groups survive");
                Check(session.Data.Groups[0].Name == "Работа" && session.Data.Groups[0].Id == groupId, "group fields");
                Check(session.Data.Entries.Count == 2, "entries survive");
                Entry mail = session.Data.Entries[0];
                Check(mail.Login == "ivan" && mail.Password == "s3cret" && mail.Description == "Почта" && mail.GroupId == groupId, "entry fields");
                Check(session.Data.Entries[1].GroupId == null, "ungrouped entry");
                DateTime created;
                Check(VaultData.TryParseTimestamp(mail.Created, out created), "created timestamp parses");
                Check(Math.Abs((DateTime.Now - created).TotalMinutes) < 5, "created timestamp is now");
            }

            ExpectVaultError(VaultError.Io, delegate { VaultSession.Create(path, Password, FastIterations); });
            ExpectVaultError(VaultError.Io, delegate { VaultSession.Open(path + ".missing", Password); });
        }

        private static void SessionWrongPassword()
        {
            string path = NewVaultPath("wrong");
            using (VaultSession session = VaultSession.Create(path, Password, FastIterations))
            {
                Check(session.VerifyPassword(Password), "verify accepts the right password");
                Check(!session.VerifyPassword(Password + "x"), "verify rejects a wrong password");
                Check(!session.VerifyPassword(""), "verify rejects an empty password");
            }

            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, "correct horse battery stapl"); });
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password.ToUpperInvariant()); });
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, ""); });
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password + " "); });

            using (VaultSession ok = VaultSession.Open(path, Password))
            {
                Check(ok.Data != null, "right password still works");
            }

            // Не хранилище вовсе.
            string foreign = Path.Combine(workDir, "foreign.vault");
            File.WriteAllText(foreign, "just a text file, not a vault");
            ExpectVaultError(VaultError.BadFormat, delegate { VaultSession.Open(foreign, Password); });
            File.WriteAllBytes(foreign, new byte[0]);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultSession.Open(foreign, Password); });
        }

        private static void SessionBackup()
        {
            string path = NewVaultPath("backup");
            string backup = VaultSession.BackupPath(path);
            using (VaultSession session = VaultSession.Create(path, Password, FastIterations))
            {
                Check(!File.Exists(backup), "no backup after the first write");

                session.Data.AddEntry(null, "first", "1", "one");
                session.Save();
                Check(File.Exists(backup), "backup appears on the second write");

                session.Data.AddEntry(null, "second", "2", "two");
                session.Save();
            }

            using (VaultSession current = VaultSession.Open(path, Password))
            {
                Check(current.Data.Entries.Count == 2, "current file has both entries");
            }
            using (VaultSession previous = VaultSession.Open(backup, Password))
            {
                Check(previous.Data.Entries.Count == 1, "backup holds the previous version");
            }
            Check(!File.Exists(AtomicFile.TempPath(path)), "no temporary file is left");

            // Остаток от прерванной записи не мешает следующему сохранению.
            File.WriteAllText(AtomicFile.TempPath(path), "stale leftover");
            using (VaultSession session = VaultSession.Open(path, Password))
            {
                session.Data.AddEntry(null, "third", "3", "three");
                session.Save();
            }
            Check(!File.Exists(AtomicFile.TempPath(path)), "stale temporary file is replaced");
            using (VaultSession current = VaultSession.Open(path, Password))
            {
                Check(current.Data.Entries.Count == 3, "save after a stale temporary file");
            }
        }

        private static void SessionBackupSimpleReplace()
        {
            // На части файловых систем (например, на некоторых флешках) замена файла одной
            // операцией недоступна, и запись идёт запасным путём. Он должен вести себя так же.
            AtomicFile.UseSimpleReplace = true;
            try
            {
                SessionBackup();
                SessionChangePassword();
            }
            finally
            {
                AtomicFile.UseSimpleReplace = false;
            }
        }

        private static void SessionChangePassword()
        {
            string path = NewVaultPath("change");
            string backup = VaultSession.BackupPath(path);
            const string newPassword = "новый мастер-пароль 2026";

            using (VaultSession session = VaultSession.Create(path, Password, FastIterations))
            {
                session.Data.AddEntry(null, "user", "pass", "note");
                session.Save();
                byte[] before = File.ReadAllBytes(path);

                session.ChangePassword(newPassword);
                byte[] after = File.ReadAllBytes(path);

                KdfParameters protection = session.Protection;
                Check(protection.IsArgon2 && protection.MemoryKiB == Argon2id.DefaultMemoryKiB && protection.Iterations == Argon2id.DefaultPasses &&
                      protection.Parallelism == Argon2id.DefaultParallelism, "an old vault moves to Argon2id when its password changes");
                Check(after[6] == 2 && after[8] == 2, "the file is written in format version 2");
                Check(!SameBytes(Slice(before, 14, 32), Slice(after, 24, 32)), "salt changes with the password");
                Check(session.VerifyPassword(newPassword), "session accepts the new password");
                Check(!session.VerifyPassword(Password), "session rejects the old password");

                // Сессия продолжает работать на новом ключе.
                session.Data.AddEntry(null, "user2", "pass2", "note2");
                session.Save();
            }

            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password); });
            using (VaultSession reopened = VaultSession.Open(path, newPassword))
            {
                Check(reopened.Data.Entries.Count == 2, "data survives the password change");
            }

            // Старый пароль не должен открывать и резервную копию.
            Check(File.Exists(backup), "backup exists");
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(backup, Password); });
            using (VaultSession fromBackup = VaultSession.Open(backup, newPassword))
            {
                Check(fromBackup.Data.Entries.Count >= 1, "backup opens with the new password");
            }
        }

        private static void SessionNoPlaintextOnDisk()
        {
            string path = NewVaultPath("plain");
            const string marker = "UNIQUE-MARKER-7f3a9c";
            using (VaultSession session = VaultSession.Create(path, Password, FastIterations))
            {
                Group group = session.Data.AddGroup(marker + "-group");
                session.Data.AddEntry(group.Id, marker + "-login", marker + "-password", marker + "-description");
                session.Save();
                session.Save();
            }

            string directory = Path.GetDirectoryName(path);
            string prefix = Path.GetFileName(path);
            int checkedFiles = 0;
            foreach (string file in Directory.GetFiles(directory, prefix + "*"))
            {
                byte[] bytes = File.ReadAllBytes(file);
                Check(IndexOf(bytes, Encoding.UTF8.GetBytes(marker)) < 0, "plaintext found in " + Path.GetFileName(file));
                Check(IndexOf(bytes, Encoding.Unicode.GetBytes(marker)) < 0, "plaintext (UTF-16) found in " + Path.GetFileName(file));
                Check(IndexOf(bytes, Encoding.UTF8.GetBytes(Password)) < 0, "master password found in " + Path.GetFileName(file));
                checkedFiles++;
            }
            Check(checkedFiles == 2, "only the vault and its backup are on disk, found " + checkedFiles);
        }

        private static void SessionDisposed()
        {
            string path = NewVaultPath("disposed");
            VaultSession session = VaultSession.Create(path, Password, FastIterations);
            session.Dispose();
            session.Dispose();
            Check(session.Data == null, "data is dropped on dispose");
            Check(!session.VerifyPassword(Password), "disposed session verifies nothing");
            try
            {
                session.Save();
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            throw new Exception("a disposed session must not write");
        }

        // ---------- Модель ----------

        private static void ModelGroups()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("  Работа  ");
            Check(work.Name == "Работа", "name is trimmed");
            Check(!string.IsNullOrEmpty(work.Id), "group gets an id");
            Group home = data.AddGroup("Личное");
            Check(work.Id != home.Id, "ids are unique");
            Check(data.FindGroup(work.Id) == work && data.GroupName(home.Id) == "Личное", "lookup");
            Check(data.FindGroup(null) == null && data.FindGroup("nope") == null && data.GroupName(null) == null, "lookup of a missing group");

            ExpectValidation(delegate { data.AddGroup(""); });
            ExpectValidation(delegate { data.AddGroup("   "); });
            ExpectValidation(delegate { data.AddGroup(null); });
            ExpectValidation(delegate { data.AddGroup("работа"); });          // без учёта регистра
            ExpectValidation(delegate { data.AddGroup(" РАБОТА "); });
            ExpectValidation(delegate { data.AddGroup(new string('я', VaultData.MaxGroupNameLength + 1)); });
            data.AddGroup(new string('я', VaultData.MaxGroupNameLength));
            Check(data.Groups.Count == 3, "only valid groups are added");

            data.RenameGroup(work.Id, "Работа и проекты");
            Check(work.Name == "Работа и проекты", "rename");
            data.RenameGroup(work.Id, "работа и проекты");                     // смена регистра своей же группы
            Check(work.Name == "работа и проекты", "rename to the same name in another case");
            ExpectValidation(delegate { data.RenameGroup(work.Id, "личное"); });
            ExpectValidation(delegate { data.RenameGroup(work.Id, ""); });
            ExpectValidation(delegate { data.RenameGroup("nope", "X"); });

            Check(data.ValidateGroupName("Новая", null, null) == null, "validation accepts a new name");
            Check(data.ValidateGroupName("Личное", null, home.Id) == null, "validation ignores the group itself");
            Check(data.ValidateGroupName("Личное", null, null) != null, "validation reports a duplicate");
        }

        private static void ModelEntries()
        {
            VaultData data = VaultData.CreateEmpty();
            Group group = data.AddGroup("Сайты");

            Entry entry = data.AddEntry(group.Id, "  ivan@example.com ", "  пароль с пробелами  ", " Почта\r\nвторая строка ");
            Check(entry.Login == "ivan@example.com", "login is trimmed");
            Check(entry.Password == "  пароль с пробелами  ", "password is stored exactly as typed");
            Check(entry.Description == "Почта\nвторая строка", "description is trimmed, line breaks are normalised");
            Check(entry.GroupId == group.Id, "group is assigned");
            Check(entry.Created == entry.Modified && entry.Created.EndsWith("Z"), "timestamps");

            ExpectValidation(delegate { data.AddEntry(null, "", "only password", "  "); });
            ExpectValidation(delegate { data.AddEntry("no-such-group", "login", "p", "d"); });
            ExpectValidation(delegate { data.AddEntry(null, new string('x', VaultData.MaxLoginLength + 1), "", ""); });
            ExpectValidation(delegate { data.AddEntry(null, "x", new string('x', VaultData.MaxPasswordLength + 1), ""); });
            ExpectValidation(delegate { data.AddEntry(null, "x", "", new string('x', VaultData.MaxDescriptionLength + 1)); });
            Check(data.Entries.Count == 1, "invalid entries are not added");

            Entry loginOnly = data.AddEntry(null, "admin", "", "");
            Entry descriptionOnly = data.AddEntry(null, "", "1234", "PIN карты");
            Check(loginOnly.GroupId == null && descriptionOnly.Login == "", "partial entries are allowed");

            string modifiedBefore = entry.Modified;
            Check(!data.UpdateEntry(entry.Id, group.Id, "ivan@example.com", "  пароль с пробелами  ", "Почта\nвторая строка"), "no-op update reports no change");
            Check(entry.Modified == modifiedBefore, "no-op update keeps the timestamp");

            Check(data.UpdateEntry(entry.Id, null, "ivan@example.com", "новый", "Почта"), "update reports a change");
            Check(entry.Password == "новый" && entry.Description == "Почта" && entry.GroupId == null, "update applies fields");
            ExpectValidation(delegate { data.UpdateEntry(entry.Id, null, "", "p", ""); });
            ExpectValidation(delegate { data.UpdateEntry("nope", null, "l", "p", "d"); });
            ExpectValidation(delegate { data.UpdateEntry(entry.Id, "no-such-group", "l", "p", "d"); });
            Check(entry.Login == "ivan@example.com", "a rejected update changes nothing");

            Check(data.DeleteEntries(new[] { loginOnly.Id, "nope" }) == 1, "delete counts only existing entries");
            Check(data.Entries.Count == 2 && data.FindEntry(loginOnly.Id) == null, "entry is gone");
            Check(data.DeleteEntries(new string[0]) == 0, "deleting nothing");
        }

        private static void ModelMove()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group home = data.AddGroup("Личное");
            Entry a = data.AddEntry(work.Id, "a", "1", "A");
            Entry b = data.AddEntry(work.Id, "b", "2", "B");
            Entry c = data.AddEntry(null, "c", "3", "C");
            string modified = a.Modified;

            Check(data.MoveEntries(new[] { a.Id, c.Id }, home.Id) == 2, "two entries move");
            Check(a.GroupId == home.Id && c.GroupId == home.Id && b.GroupId == work.Id, "groups after the move");
            Check(a.Modified == modified, "moving does not touch the content timestamp");

            Check(data.MoveEntries(new[] { a.Id, b.Id }, home.Id) == 1, "only entries that actually change are counted");
            Check(data.MoveEntries(new[] { a.Id, b.Id, c.Id }, null) == 3, "move out of all groups");
            Check(a.GroupId == null && b.GroupId == null && c.GroupId == null, "entries are ungrouped");
            Check(data.MoveEntries(new[] { a.Id }, "") == 0, "empty id means no group");

            ExpectValidation(delegate { data.MoveEntries(new[] { a.Id }, "no-such-group"); });
            Check(data.MoveEntries(new[] { "nope" }, work.Id) == 0, "unknown entries are ignored");

            int ungrouped;
            data.MoveEntries(new[] { a.Id, b.Id }, work.Id);
            Dictionary<string, int> counts = data.CountByGroup(out ungrouped);
            Check(counts[work.Id] == 2 && counts[home.Id] == 0 && ungrouped == 1, "counts per group");
        }

        private static void ModelDeleteGroup()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group home = data.AddGroup("Личное");
            Entry a = data.AddEntry(work.Id, "a", "1", "A");
            Entry b = data.AddEntry(work.Id, "b", "2", "B");
            Entry c = data.AddEntry(home.Id, "c", "3", "C");

            Check(data.DeleteGroup(work.Id) == 2, "two entries are released");
            Check(data.Groups.Count == 1 && data.FindGroup(work.Id) == null, "group is gone");
            Check(data.Entries.Count == 3, "entries are kept");
            Check(a.GroupId == null && b.GroupId == null && c.GroupId == home.Id, "released entries are ungrouped");
            ExpectValidation(delegate { data.DeleteGroup(work.Id); });

            // Название освободилось.
            data.AddGroup("Работа");
            Check(data.DeleteGroup(home.Id) == 1, "second group");
        }

        private static void ModelQuery()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group home = data.AddGroup("Личное");
            data.AddEntry(work.Id, "ivan@corp.example", "p1", "Корпоративная почта");
            data.AddEntry(work.Id, "admin", "p2", "Сервер GitLab");
            data.AddEntry(home.Id, "ivan@example.org", "p3", "Почта Gmail");
            data.AddEntry(null, "7001234567", "НайдиМеня", "Госуслуги");

            Check(data.Query(GroupFilter.All, null).Count == 4, "all");
            Check(data.Query(GroupFilter.All, "   ").Count == 4, "blank search");
            Check(data.Query(GroupFilter.ForGroup(work.Id), "").Count == 2, "by group");
            Check(data.Query(GroupFilter.Ungrouped, "").Count == 1, "ungrouped");
            Check(data.Query(GroupFilter.ForGroup("nope"), "").Count == 0, "unknown group");

            Check(data.Query(GroupFilter.All, "почта").Count == 2, "search in description, case-insensitive");
            Check(data.Query(GroupFilter.All, "ПОЧТА").Count == 2, "search upper case");
            Check(data.Query(GroupFilter.All, "IVAN").Count == 2, "search in login");
            Check(data.Query(GroupFilter.All, "ivan gmail").Count == 1, "all words must match");
            Check(data.Query(GroupFilter.All, "личное").Count == 1, "search by group name");
            Check(data.Query(GroupFilter.ForGroup(work.Id), "почта").Count == 1, "search inside a group");
            Check(data.Query(GroupFilter.All, "НайдиМеня").Count == 0, "passwords are not searched");
            Check(data.Query(GroupFilter.All, "нет такого").Count == 0, "no match");

            Check(GroupFilter.ForEntryGroup(null).Kind == FilterKind.Ungrouped, "filter for an ungrouped entry");
            Check(GroupFilter.ForEntryGroup(work.Id).SameAs(GroupFilter.ForGroup(work.Id)), "filter for a grouped entry");
            Check(!GroupFilter.ForGroup(work.Id).SameAs(GroupFilter.ForGroup(home.Id)), "different groups differ");
            Check(GroupFilter.All.SameAs(GroupFilter.All) && !GroupFilter.All.SameAs(GroupFilter.Ungrouped), "filter comparison");
        }

        // ---------- Вложенные группы ----------

        /// <summary>Порядок соседних групп в тестах: по названию без учёта регистра.</summary>
        private static int ByName(string a, string b)
        {
            return string.Compare(a, b, StringComparison.OrdinalIgnoreCase);
        }

        private static string Names(List<Group> groups)
        {
            var names = new List<string>();
            foreach (Group group in groups) names.Add(group.Name);
            return string.Join(", ", names.ToArray());
        }

        private static int CountOf(string text, string part)
        {
            int count = 0;
            for (int index = text.IndexOf(part, StringComparison.Ordinal); index >= 0; index = text.IndexOf(part, index + part.Length, StringComparison.Ordinal))
            {
                count++;
            }
            return count;
        }

        private static void NestedGroups()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group projects = data.AddGroup(" Проекты ", work.Id);
            Group servers = data.AddGroup("Серверы", work.Id);
            Group alpha = data.AddGroup("Альфа", projects.Id);
            Group home = data.AddGroup("Личное");

            Check(work.ParentId == null && home.ParentId == null, "top-level groups have no parent");
            Check(projects.Name == "Проекты" && projects.ParentId == work.Id && alpha.ParentId == projects.Id && servers.ParentId == work.Id, "parent links");

            Check(data.GroupPath(work.Id) == "Работа", "path of a top-level group");
            Check(data.GroupPath(alpha.Id) == "Работа / Проекты / Альфа", "path of a nested group: " + data.GroupPath(alpha.Id));
            Check(data.GroupPath(null) == null && data.GroupPath("nope") == null, "path of a missing group");
            Check(data.GroupName(alpha.Id) == "Альфа", "plain name of a nested group");

            Check(data.DepthOf(work.Id) == 1 && data.DepthOf(projects.Id) == 2 && data.DepthOf(alpha.Id) == 3 && data.DepthOf("nope") == 0, "depth");
            Check(Names(data.ChildrenOf(null)) == "Работа, Личное", "top-level groups: " + Names(data.ChildrenOf(null)));
            Check(Names(data.ChildrenOf("")) == "Работа, Личное", "an empty id also means the top level");
            Check(Names(data.ChildrenOf(work.Id)) == "Проекты, Серверы", "children of a group: " + Names(data.ChildrenOf(work.Id)));
            Check(data.ChildrenOf(alpha.Id).Count == 0, "a leaf has no children");
            Check(data.DescendantsOf(work.Id).Count == 3 && data.DescendantsOf(home.Id).Count == 0 && data.DescendantsOf(null).Count == 0, "descendants");
            Check(Names(data.TreeOrder(ByName)) == "Личное, Работа, Проекты, Альфа, Серверы", "tree order: " + Names(data.TreeOrder(ByName)));

            // Одинаковые названия допустимы в разных группах, но не среди соседних.
            Group homeProjects = data.AddGroup("проекты", home.Id);
            Check(homeProjects.ParentId == home.Id, "the same name under another parent");
            data.AddGroup("Работа", work.Id);
            ExpectValidation(delegate { data.AddGroup("ПРОЕКТЫ", work.Id); });
            ExpectValidation(delegate { data.AddGroup("личное"); });
            ExpectValidation(delegate { data.AddGroup("Новая", "no-such-group"); });
            ExpectValidation(delegate { data.AddGroup("", work.Id); });
            Check(data.ValidateGroupName("Проекты", work.Id, null).Contains("Работа"), "the error names the parent group");
            Check(data.ValidateGroupName("Проекты", work.Id, projects.Id) == null, "a group does not clash with itself");
            Check(data.ValidateGroupName("Проекты", null, null) == null, "the name is free on the top level");
            Check(data.Groups.Count == 7, "only valid groups are added: " + data.Groups.Count);

            // Счётчики — только свои записи, без подгрупп.
            data.AddEntry(work.Id, "w", "1", "в самой группе");
            data.AddEntry(alpha.Id, "a", "2", "глубоко");
            data.AddEntry(alpha.Id, "b", "3", "глубоко 2");
            int ungrouped;
            Dictionary<string, int> counts = data.CountByGroup(out ungrouped);
            Check(counts[work.Id] == 1 && counts[projects.Id] == 0 && counts[alpha.Id] == 2 && ungrouped == 0, "direct counts");
            Check(data.CountInBranch(work.Id) == 3 && data.CountInBranch(projects.Id) == 2 && data.CountInBranch(home.Id) == 0, "branch counts");
        }

        private static void NestedGroupsMove()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group projects = data.AddGroup("Проекты", work.Id);
            Group alpha = data.AddGroup("Альфа", projects.Id);
            Group home = data.AddGroup("Личное");
            Entry entry = data.AddEntry(alpha.Id, "a", "1", "запись");

            // Ветка переносится целиком: подгруппы и записи едут вместе с группой.
            Check(data.MoveGroup(projects.Id, home.Id), "a move reports a change");
            Check(projects.ParentId == home.Id && alpha.ParentId == projects.Id && entry.GroupId == alpha.Id, "the branch moves as a whole");
            Check(data.GroupPath(alpha.Id) == "Личное / Проекты / Альфа", "path after the move");
            Check(!data.MoveGroup(projects.Id, home.Id), "moving to the same place changes nothing");

            Check(data.MoveGroup(projects.Id, null), "move to the top level");
            Check(projects.ParentId == null && data.DepthOf(alpha.Id) == 2, "the group is on the top level");
            Check(!data.MoveGroup(projects.Id, ""), "an empty id means the top level");

            // Запрещённые переносы.
            ExpectValidation(delegate { data.MoveGroup(projects.Id, projects.Id); });
            ExpectValidation(delegate { data.MoveGroup(projects.Id, alpha.Id); });
            ExpectValidation(delegate { data.MoveGroup(projects.Id, "no-such-group"); });
            ExpectValidation(delegate { data.MoveGroup("no-such-group", work.Id); });
            Check(projects.ParentId == null, "a rejected move changes nothing");
            Check(data.ValidateGroupParent(projects.Id, alpha.Id) != null && data.ValidateGroupParent(projects.Id, work.Id) == null, "placement check");

            // Совпадение названий в новом месте.
            Group clash = data.AddGroup("Проекты", work.Id);
            ExpectValidation(delegate { data.MoveGroup(projects.Id, work.Id); });
            Check(data.ValidateGroupParent(projects.Id, work.Id) == null, "the place itself is fine, only the name clashes");

            // Переименование и перенос одной операцией.
            Check(data.UpdateGroup(projects.Id, "Старые проекты", work.Id), "rename and move together");
            Check(projects.Name == "Старые проекты" && projects.ParentId == work.Id, "both changes are applied");
            Check(!data.UpdateGroup(projects.Id, " Старые проекты ", work.Id), "the same values change nothing");
            ExpectValidation(delegate { data.UpdateGroup(projects.Id, "проекты", work.Id); });
            ExpectValidation(delegate { data.UpdateGroup(projects.Id, "", work.Id); });
            Check(projects.Name == "Старые проекты" && projects.ParentId == work.Id, "a rejected update changes nothing");

            // Переименование не трогает место в дереве.
            data.RenameGroup(alpha.Id, "Бета");
            Check(alpha.Name == "Бета" && alpha.ParentId == projects.Id, "rename keeps the parent");
            Check(clash.ParentId == work.Id && clash.Name == "Проекты", "other groups are untouched");
        }

        private static void NestedGroupsDepthLimit()
        {
            VaultData data = VaultData.CreateEmpty();
            Group top = data.AddGroup("Уровень 1");
            Group current = top;
            for (int level = 2; level <= VaultData.MaxGroupDepth; level++)
            {
                current = data.AddGroup("Уровень " + level, current.Id);
            }
            string deepest = current.Id;
            string almostDeepest = current.ParentId;
            Check(data.DepthOf(deepest) == VaultData.MaxGroupDepth, "the deepest allowed level");
            ExpectValidation(delegate { data.AddGroup("Слишком глубоко", deepest); });
            Check(data.ValidateGroupParent(null, deepest).Contains(VaultData.MaxGroupDepth.ToString()), "the error names the limit");

            // При переносе считается вся ветка, а не только сама группа.
            Group branch = data.AddGroup("Ветка");
            Group leaf = data.AddGroup("Лист", branch.Id);
            ExpectValidation(delegate { data.MoveGroup(branch.Id, almostDeepest); });
            Check(branch.ParentId == null, "a branch that would be too deep stays where it was");

            Check(data.MoveGroup(leaf.Id, almostDeepest), "a single group still fits there");
            Check(data.DepthOf(leaf.Id) == VaultData.MaxGroupDepth, "it sits on the last level");
            Check(data.MoveGroup(branch.Id, data.ChildrenOf(top.Id)[0].Id), "the branch fits higher up");
            Check(data.DepthOf(branch.Id) == 3, "depth of the moved branch");
        }

        private static void NestedGroupsDelete()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group projects = data.AddGroup("Проекты", work.Id);
            Group alpha = data.AddGroup("Альфа", projects.Id);
            Group beta = data.AddGroup("Бета", projects.Id);
            Group servers = data.AddGroup("Серверы", work.Id);
            Group home = data.AddGroup("Личное");
            Entry inWork = data.AddEntry(work.Id, "w", "1", "W");
            Entry inProjects = data.AddEntry(projects.Id, "p", "2", "P");
            Entry inAlpha = data.AddEntry(alpha.Id, "a", "3", "A");
            Entry inBeta = data.AddEntry(beta.Id, "b", "4", "B");
            Entry inServers = data.AddEntry(servers.Id, "s", "5", "S");
            Entry inHome = data.AddEntry(home.Id, "h", "6", "H");

            // Группа из середины дерева: её подгруппы исчезают, записи поднимаются к родителю.
            Check(data.DeleteGroup(projects.Id) == 3, "three entries move up");
            Check(data.FindGroup(projects.Id) == null && data.FindGroup(alpha.Id) == null && data.FindGroup(beta.Id) == null, "the branch is gone");
            Check(data.Groups.Count == 3, "other groups stay");
            Check(inProjects.GroupId == work.Id && inAlpha.GroupId == work.Id && inBeta.GroupId == work.Id, "entries land in the parent group");
            Check(inWork.GroupId == work.Id && inServers.GroupId == servers.Id && inHome.GroupId == home.Id, "other entries are untouched");
            Check(data.Entries.Count == 6, "no entry is deleted");

            // Группа верхнего уровня: записи всей ветки остаются без группы.
            Check(data.DeleteGroup(work.Id) == 5, "entries of the whole branch are released");
            Check(data.Groups.Count == 1 && data.Groups[0] == home, "only the unrelated group is left");
            Check(inWork.GroupId == null && inServers.GroupId == null && inAlpha.GroupId == null, "entries become ungrouped");
            Check(inHome.GroupId == home.Id && data.Entries.Count == 6, "the rest is intact");
            ExpectValidation(delegate { data.DeleteGroup(projects.Id); });
        }

        private static void NestedGroupsQuery()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group projects = data.AddGroup("Проекты", work.Id);
            Group home = data.AddGroup("Личное");
            data.AddEntry(work.Id, "boss", "1", "Почта начальника");
            data.AddEntry(projects.Id, "dev", "2", "Сервер сборки");
            data.AddEntry(projects.Id, "qa", "3", "Стенд");
            data.AddEntry(home.Id, "me", "4", "Почта");

            // Группа показывает только свои записи; подгруппы — отдельно.
            Check(data.Query(GroupFilter.ForGroup(work.Id), "").Count == 1, "a parent group lists its own entries only");
            Check(data.Query(GroupFilter.ForGroup(projects.Id), "").Count == 2, "a subgroup lists its entries");

            // Поиск идёт по пути к группе: по названию родителя находятся и записи подгрупп.
            Check(data.Query(GroupFilter.All, "работа").Count == 3, "search by the parent name finds entries of subgroups");
            Check(data.Query(GroupFilter.All, "проекты").Count == 2, "search by the subgroup name");
            Check(data.Query(GroupFilter.All, "работа стенд").Count == 1, "group name and description together");
            Check(data.Query(GroupFilter.All, "личное сервер").Count == 0, "words from different entries do not combine");

            Dictionary<string, string> paths = data.GroupPaths();
            Check(paths.Count == 3 && paths[projects.Id] == "Работа / Проекты" && paths[home.Id] == "Личное", "paths of all groups");
        }

        private static void NestedGroupsJson()
        {
            // Без вложенности файл остаётся версии 1 и не содержит новых полей.
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            data.AddEntry(work.Id, "l", "p", "d");
            string flatJson = Encoding.UTF8.GetString(data.ToJson());
            Check(flatJson.Contains("\"version\":1") && !flatJson.Contains("parentId"), "flat data is written as version 1: " + flatJson);

            // С вложенностью — версия 2, поле parentId только у вложенных групп.
            Group projects = data.AddGroup("Проекты", work.Id);
            Group alpha = data.AddGroup("Альфа", projects.Id);
            string nestedJson = Encoding.UTF8.GetString(data.ToJson());
            Check(nestedJson.Contains("\"version\":2"), "nested data is written as version 2");
            Check(CountOf(nestedJson, "\"parentId\"") == 2, "parentId is written for nested groups only: " + nestedJson);

            VaultData copy = FromJsonText(nestedJson);
            Check(copy.Version == 2 && copy.Groups.Count == 3, "nested data is read back");
            Check(copy.FindGroup(alpha.Id).ParentId == projects.Id && copy.FindGroup(work.Id).ParentId == null, "links survive");
            Check(copy.GroupPath(alpha.Id) == "Работа / Проекты / Альфа", "path after reading");

            // Когда вложенность убрали, файл снова версии 1.
            copy.MoveGroup(projects.Id, null);
            copy.MoveGroup(alpha.Id, null);
            Check(Encoding.UTF8.GetString(copy.ToJson()).Contains("\"version\":1"), "the version drops back to 1");

            // Файл версии 1 (без parentId) читается как раньше.
            VaultData old = FromJsonText("{\"version\":1,\"groups\":[{\"id\":\"g1\",\"name\":\"A\"}],\"entries\":[{\"id\":\"e1\",\"groupId\":\"g1\",\"login\":\"l\"}]}");
            Check(old.Groups[0].ParentId == null && old.Entries[0].GroupId == "g1" && old.Version == 1, "a version 1 file");

            // Испорченные ссылки: несуществующий родитель, ссылка на себя, кольца из двух и трёх групп.
            VaultData broken = FromJsonText(
                "{\"version\":2,\"groups\":[" +
                "{\"id\":\"a\",\"name\":\"A\",\"parentId\":\"gone\"}," +
                "{\"id\":\"b\",\"name\":\"B\",\"parentId\":\"b\"}," +
                "{\"id\":\"c\",\"name\":\"C\",\"parentId\":\"d\"}," +
                "{\"id\":\"d\",\"name\":\"D\",\"parentId\":\"c\"}," +
                "{\"id\":\"e\",\"name\":\"E\",\"parentId\":\"g\"}," +
                "{\"id\":\"f\",\"name\":\"F\",\"parentId\":\"e\"}," +
                "{\"id\":\"g\",\"name\":\"G\",\"parentId\":\"f\"}," +
                "{\"id\":\"h\",\"name\":\"H\",\"parentId\":\"a\"}," +
                "{\"id\":\"i\",\"name\":\"I\",\"parentId\":\"\"}]," +
                "\"entries\":[{\"id\":\"e1\",\"groupId\":\"d\",\"login\":\"l\"}]}");
            Check(broken.FindGroup("a").ParentId == null, "a missing parent is dropped");
            Check(broken.FindGroup("b").ParentId == null, "a self reference is dropped");
            Check(broken.FindGroup("i").ParentId == null, "an empty parent id means the top level");
            Check(broken.FindGroup("h").ParentId == "a", "a valid link is kept");
            Check(broken.TreeOrder(ByName).Count == broken.Groups.Count,
                "after the rings are broken every group is reachable in the tree: " + Names(broken.TreeOrder(ByName)));
            foreach (Group group in broken.Groups)
            {
                Check(broken.DepthOf(group.Id) >= 1 && broken.DepthOf(group.Id) <= broken.Groups.Count, "depth is finite for " + group.Name);
                Check(broken.GroupPath(group.Id) != null, "a path exists for " + group.Name);
            }
            Check(broken.Entries[0].GroupId == "d", "entries keep their group");

            VaultData again = VaultData.FromJson(broken.ToJson());
            Check(again.Groups.Count == broken.Groups.Count && again.TreeOrder(ByName).Count == again.Groups.Count, "repaired data round-trips");
        }

        // ---------- JSON ----------

        private static void JsonSpecialCharacters()
        {
            string[] samples =
            {
                "простой текст",
                "кавычки \" и ' и «ёлочки»",
                "обратная косая \\ и прямая / и </script>",
                "табуляция\tи перевод\nстроки",
                "управляющие " + (char)0x01 + (char)0x1F + " символы",
                "эмодзи " + Key + char.ConvertFromUtf32(0x1F600) + " и 日本語 и العربية",
                "\\/Date(1234567890)\\/",
                "{\"json\":[1,2,3]}",
                "  пробелы по краям  ",
                "" + (char)0x2028 + (char)0x2029 + " разделители строк Юникода",
                ""
            };

            VaultData data = VaultData.CreateEmpty();
            Group group = data.AddGroup("Группа \"с кавычками\" \\ / " + Key);
            foreach (string sample in samples)
            {
                data.AddEntry(group.Id, "login " + sample, sample, "description " + sample);
            }

            byte[] json = data.ToJson();
            VaultData copy = VaultData.FromJson(json);

            Check(copy.Version == 1, "data without nested groups keeps structure version 1");
            Check(copy.Groups.Count == 1 && copy.Groups[0].Name == group.Name && copy.Groups[0].Id == group.Id, "group survives");
            Check(copy.Entries.Count == samples.Length, "entry count");
            for (int i = 0; i < samples.Length; i++)
            {
                Entry original = data.Entries[i];
                Entry restored = copy.Entries[i];
                Check(restored.Id == original.Id && restored.GroupId == original.GroupId, "ids, sample " + i);
                Check(restored.Login == original.Login, "login, sample " + i);
                Check(restored.Password == samples[i], "password, sample " + i);
                Check(restored.Description == original.Description, "description, sample " + i);
                Check(restored.Created == original.Created && restored.Modified == original.Modified, "timestamps, sample " + i);
            }

            // Имена полей в JSON — часть формата.
            string text = Encoding.UTF8.GetString(json);
            foreach (string field in new[] { "\"version\":1", "\"groups\":[", "\"entries\":[", "\"id\":", "\"name\":", "\"groupId\":", "\"login\":", "\"password\":", "\"description\":", "\"created\":", "\"modified\":" })
            {
                Check(text.Contains(field), "json field " + field);
            }
        }

        private static void JsonNormalisation()
        {
            // Неполные данные приводятся к согласованному виду.
            VaultData sparse = FromJsonText("{\"version\":1}");
            Check(sparse.Groups != null && sparse.Groups.Count == 0 && sparse.Entries != null && sparse.Entries.Count == 0, "missing lists become empty");

            VaultData messy = FromJsonText(
                "{\"groups\":[{\"id\":\"g1\",\"name\":\" A \"},{\"id\":\"g1\",\"name\":\"B\"},{\"name\":\"\"},null]," +
                "\"entries\":[{\"id\":\"e1\",\"groupId\":\"g1\",\"login\":\"l\"},{\"id\":\"e1\",\"groupId\":\"gone\"},null,{\"unknown\":true}]," +
                "\"somethingNew\":{\"a\":1}}");
            Check(messy.Version == 1, "missing version is treated as current");
            Check(messy.Groups.Count == 3, "null group is dropped");
            Check(messy.Groups[0].Name == "A" && messy.Groups[2].Name == "Группа", "group names are cleaned");
            Check(messy.Groups[0].Id != messy.Groups[1].Id && !string.IsNullOrEmpty(messy.Groups[2].Id), "group ids are made unique");
            Check(messy.Entries.Count == 3, "null entry is dropped");
            Check(messy.Entries[0].GroupId == "g1" && messy.Entries[0].Password == "" && messy.Entries[0].Description == "", "missing fields become empty");
            Check(messy.Entries[1].GroupId == null, "dangling group reference is cleared");
            Check(messy.Entries[0].Id != messy.Entries[1].Id && !string.IsNullOrEmpty(messy.Entries[2].Id), "entry ids are made unique");

            ExpectVaultError(VaultError.UnsupportedVersion, delegate { FromJsonText("{\"version\":4,\"groups\":[],\"entries\":[]}"); });
            // Не JSON или оборванный JSON — всегда ошибка формата.
            string[] broken =
            {
                "not json at all",
                "{\"version\":1,\"groups\":",
                "{\"version\":\"one\"}",
                "null",
                ""
            };
            foreach (string text in broken)
            {
                try
                {
                    FromJsonText(text);
                }
                catch (VaultException ex)
                {
                    if (ex.Error != VaultError.BadFormat) throw new Exception("expected BadFormat for <" + text + ">, got " + ex.Error);
                    continue;
                }
                throw new Exception("broken JSON was accepted: <" + text + ">");
            }

            // JSON правильный, но не той структуры. Сериализатор .NET к такому снисходителен,
            // поэтому требуем одного из двух: ошибка формата либо согласованные данные.
            // Никаких других исключений и никаких null внутри модели.
            string[] odd =
            {
                "{\"version\":1,\"groups\":{\"id\":\"g\"}}",
                "{\"version\":1,\"entries\":[1,2]}",
                "{\"version\":1,\"groups\":[[]],\"entries\":[{\"login\":{\"a\":1}}]}",
                "{\"version\":1,\"entries\":[{\"login\":123,\"password\":true}]}",
                "[1,2,3]",
                "\"text\"",
                "42",
                "{}"
            };
            foreach (string text in odd)
            {
                VaultData data;
                try
                {
                    data = FromJsonText(text);
                }
                catch (VaultException ex)
                {
                    if (ex.Error != VaultError.BadFormat) throw new Exception("expected BadFormat for <" + text + ">, got " + ex.Error);
                    continue;
                }
                Check(data.Groups != null && data.Entries != null, "lists exist for <" + text + ">");
                foreach (Group group in data.Groups)
                {
                    Check(group != null && !string.IsNullOrEmpty(group.Id) && !string.IsNullOrEmpty(group.Name), "group is consistent for <" + text + ">");
                }
                foreach (Entry entry in data.Entries)
                {
                    Check(entry != null && !string.IsNullOrEmpty(entry.Id) && entry.Login != null && entry.Password != null && entry.Description != null,
                        "entry is consistent for <" + text + ">");
                    Check(entry.GroupId == null || data.FindGroup(entry.GroupId) != null, "group reference is valid for <" + text + ">");
                }
                // И такие данные должны нормально сохраняться обратно.
                Check(VaultData.FromJson(data.ToJson()).Entries.Count == data.Entries.Count, "round trip for <" + text + ">");
            }
        }

        // ---------- Argon2id ----------

        private static void Blake2bKnownAnswers()
        {
            // RFC 7693 (приложение A) и значения, полученные независимой реализацией (OpenSSL).
            Equal("786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
                Blake2b.Hash(new byte[0], 64));
            Equal("ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                Blake2b.Hash(Ascii("abc"), 64));
            Equal("a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918",
                Blake2b.Hash(Ascii("The quick brown fox jumps over the lazy dog"), 64));

            // Данные длиннее одного блока (128 байт) и ровно в блок.
            Equal("932355851d75f09c18646a9da87c25e055bc57f113121ad1ec63d45e7a1d62ab9133f8b7d1d7de9e0afa784eb6a8a11d78683013d0a672611f17668d9577d209",
                Blake2b.Hash(Ascii(new string('a', 200)), 64));
            Check(Blake2b.Hash(Ascii(new string('a', 128)), 64).Length == 64 && Blake2b.Hash(Ascii("abc"), 32).Length == 32, "output lengths");
            NotEqual(Blake2b.Hash(Ascii(new string('a', 128)), 64), Blake2b.Hash(Ascii(new string('a', 129)), 64));
            NotEqual(Slice(Blake2b.Hash(Ascii("abc"), 64), 0, 32), Blake2b.Hash(Ascii("abc"), 32));
        }

        private static void Argon2idKnownAnswers()
        {
            // RFC 9106, раздел 5.3: с секретным ключом и дополнительными данными.
            Equal("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
                Argon2id.Hash(Filled(32, 1), Filled(16, 2), Filled(8, 3), Filled(12, 4), 3, 32, 4, 32));

            // Значения независимой реализации (OpenSSL в Node.js): разные объёмы памяти, числа
            // проходов и дорожек, длины результата; память, не кратная числу дорожек; наименьшая память.
            Equal("1a98fba8e6394425c9bdc333a9c750aaf811df070f5fb4a5788e1cf4db5793a1",
                Argon2id.Hash(Ascii("password"), Ascii("somesaltsomesalt"), 2, 64, 1, 32));
            Equal("3c57781ce2b3a6865c42a6971f3c4a6d408d5dbfa55296279645b31e512f8ae4",
                Argon2id.Hash(Ascii("password"), Ascii("somesaltsomesalt"), 1, 32, 4, 32));
            Equal("825d16b5465577271efb52ecf19aea5f37e4fdafe689dbb77d25028de8316dd2665b6663c29e0f5f6c8d893738f0c53b02f2e68e92c63efaa5fee8e380e46e55",
                Argon2id.Hash(Ascii("correct horse battery staple"), Filled(32, 7), 3, 256, 2, 64));
            Equal("8e7d5887e56c0d763d0b871b78cc9b20",
                Argon2id.Hash(Ascii("p"), Filled(16, 9), 2, 100, 3, 16));
            Equal("135fbae7bef9930c74673fcaf1fa6f666f0cd91173f1553d7033bb4e9587ff4e",
                Argon2id.Hash(new byte[0], Filled(16, 5), 1, 8, 1, 32));
            Equal("b371df12c9a5259a478dd4f6d9d3613c58220638edb3bbcb0819675faa553f3b",
                Argon2id.Hash(Encoding.UTF8.GetBytes("длинный пароль"), Filled(32, 0xAB), 2, 4096, 4, 32));
        }

        private static void Argon2idProperties()
        {
            byte[] password = Ascii("password");
            byte[] salt = Filled(16, 1);
            byte[] reference = Argon2id.Hash(password, salt, 2, 64, 2, 32);

            Equal(reference, Argon2id.Hash(password, salt, 2, 64, 2, 32));
            NotEqual(reference, Argon2id.Hash(Ascii("passwore"), salt, 2, 64, 2, 32));
            NotEqual(reference, Argon2id.Hash(password, Filled(16, 2), 2, 64, 2, 32));
            NotEqual(reference, Argon2id.Hash(password, salt, 3, 64, 2, 32));
            NotEqual(reference, Argon2id.Hash(password, salt, 2, 128, 2, 32));
            NotEqual(reference, Argon2id.Hash(password, salt, 2, 64, 1, 32));
            NotEqual(reference, Slice(Argon2id.Hash(password, salt, 2, 64, 2, 64), 0, 32));

            // Параллельное заполнение дорожек даёт тот же результат при каждом запуске.
            byte[] parallel = Argon2id.Hash(password, salt, 2, 1024, 8, 32);
            for (int i = 0; i < 5; i++)
            {
                Equal(parallel, Argon2id.Hash(password, salt, 2, 1024, 8, 32));
            }

            ExpectArgument(delegate { Argon2id.Hash(password, salt, 0, 64, 1, 32); });
            ExpectArgument(delegate { Argon2id.Hash(password, salt, 1, 7, 1, 32); });
            ExpectArgument(delegate { Argon2id.Hash(password, salt, 1, 15, 2, 32); });
            ExpectArgument(delegate { Argon2id.Hash(password, salt, 1, 64, 0, 32); });
            ExpectArgument(delegate { Argon2id.Hash(password, new byte[7], 1, 64, 1, 32); });
            ExpectArgument(delegate { Argon2id.Hash(password, salt, 1, 64, 1, 3); });
        }

        private static byte[] Filled(int length, byte value)
        {
            var bytes = new byte[length];
            for (int i = 0; i < length; i++) bytes[i] = value;
            return bytes;
        }

        private static void ExpectArgument(Action action)
        {
            try
            {
                action();
            }
            catch (ArgumentException)
            {
                return;
            }
            throw new Exception("expected the arguments to be refused");
        }

        // ---------- Формат версии 2 и ключевой файл ----------

        /// <summary>Параметры Argon2id поменьше обычных — чтобы тесты формата шли быстро.</summary>
        private static KdfParameters SmallArgon2(byte[] salt, bool keyFile)
        {
            KdfParameters kdf = KdfParameters.Argon2(salt, keyFile);
            kdf.Iterations = 1;
            kdf.MemoryKiB = 256;
            kdf.Parallelism = 2;
            return kdf;
        }

        private static void FormatVersion2()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            byte[] plain = Encoding.UTF8.GetBytes("{\"version\":1,\"groups\":[],\"entries\":[]}");
            byte[] keyFileHash = VaultFormat.HashKeyFile(Ascii("the key file"));

            // Раскладка заголовка.
            KdfParameters kdf = SmallArgon2(salt, true);
            byte[] key = VaultFormat.DeriveKey(Password, keyFileHash, kdf);
            byte[] file = VaultFormat.Seal(key, kdf, plain);
            Check(file.Length == 68 + plain.Length + 16, "file length");
            Check(Encoding.ASCII.GetString(file, 0, 6) == "KEYBOX" && file[6] == 2 && file[7] == 0, "signature and format version");
            Check(file[8] == 2 && file[9] == 1 && file[10] == 1 && file[11] == 0, "Argon2id, AES-256-GCM, key file flag, reserved byte");
            Check(BitConverter.ToInt32(file, 12) == 1 && BitConverter.ToInt32(file, 16) == 256 && BitConverter.ToInt32(file, 20) == 2, "passes, memory, lanes");
            Equal(salt, Slice(file, 24, 32));

            VaultHeader header = VaultFormat.ParseHeader(file);
            Check(header.FormatVersion == 2 && header.Size == 68 && header.Kdf.IsArgon2 && header.Kdf.KeyFile, "parsed header");
            Check(header.Kdf.Iterations == 1 && header.Kdf.MemoryKiB == 256 && header.Kdf.Parallelism == 2, "parsed parameters");
            Equal(salt, header.Salt);
            Equal(Slice(file, 56, 12), header.Nonce);
            Equal(plain, VaultFormat.Open(key, file));

            // Любой изменённый байт — заголовка, данных или тега — обнаруживается.
            for (int i = 0; i < file.Length; i++)
            {
                byte[] damaged = (byte[])file.Clone();
                damaged[i] ^= 0x01;
                bool rejected = false;
                try
                {
                    VaultFormat.Open(key, damaged);
                }
                catch (VaultException)
                {
                    rejected = true;
                }
                Check(rejected, "a flipped bit in byte " + i + " is detected");
            }

            // Без ключевого файла ключ другой; с другим файлом — тоже.
            KdfParameters withoutFile = SmallArgon2(salt, false);
            NotEqual(key, VaultFormat.DeriveKey(Password, null, withoutFile));
            NotEqual(key, VaultFormat.DeriveKey(Password, VaultFormat.HashKeyFile(Ascii("another file")), kdf));
            ExpectVaultError(VaultError.KeyFileRequired, delegate { VaultFormat.DeriveKey(Password, null, kdf); });

            // Секрет с ключевым файлом: HMAC-SHA512(SHA-512(файл), пароль) — сверка с независимым вычислением.
            byte[] expectedSecret;
            using (var hmac = new HMACSHA512(keyFileHash))
            {
                expectedSecret = hmac.ComputeHash(Encoding.UTF8.GetBytes(Password));
            }
            Equal(Argon2id.Hash(expectedSecret, salt, 1, 256, 2, 32), key);
            Equal(Argon2id.Hash(Encoding.UTF8.GetBytes(Password), salt, 1, 256, 2, 32), VaultFormat.DeriveKey(Password, null, withoutFile));

            // PBKDF2 с ключевым файлом тоже пишется в формате 2; без него — по-прежнему в формате 1.
            KdfParameters pbkdf2 = KdfParameters.Pbkdf2(FastIterations, salt);
            pbkdf2.KeyFile = true;
            byte[] pbkdf2Key = VaultFormat.DeriveKey(Password, keyFileHash, pbkdf2);
            byte[] pbkdf2File = VaultFormat.Seal(pbkdf2Key, pbkdf2, plain);
            Check(pbkdf2File[6] == 2 && pbkdf2File[8] == 1 && pbkdf2File[10] == 1 && BitConverter.ToInt32(pbkdf2File, 12) == FastIterations &&
                  BitConverter.ToInt32(pbkdf2File, 16) == 0 && BitConverter.ToInt32(pbkdf2File, 20) == 0, "PBKDF2 with a key file in format 2");
            Equal(plain, VaultFormat.Open(pbkdf2Key, pbkdf2File));
            byte[] oldStyle = VaultFormat.Seal(VaultFormat.DeriveKey(Password, salt, FastIterations), KdfParameters.Pbkdf2(FastIterations, salt), plain);
            Check(oldStyle[6] == 1 && oldStyle.Length == 58 + plain.Length + 16, "PBKDF2 without a key file stays in format 1");

            // Значения из заголовка проверяются до того, как под них выделится память.
            byte[] hungry = (byte[])file.Clone();
            WriteInt32(hungry, 16, VaultFormat.MaxArgon2MemoryKiB + 1);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(hungry); });
            byte[] endless = (byte[])file.Clone();
            WriteInt32(endless, 12, VaultFormat.MaxArgon2Passes + 1);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(endless); });
            byte[] heavy = (byte[])file.Clone();
            WriteInt32(heavy, 12, 64);
            WriteInt32(heavy, 16, VaultFormat.MaxArgon2MemoryKiB);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(heavy); });
            byte[] tiny = (byte[])file.Clone();
            WriteInt32(tiny, 16, 15);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(tiny); });
            byte[] noLanes = (byte[])file.Clone();
            WriteInt32(noLanes, 20, 0);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(noLanes); });
            byte[] negative = (byte[])file.Clone();
            WriteInt32(negative, 16, -1);
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(negative); });

            // Незнакомые признаки и версии — «обновите программу», а не «файл повреждён».
            byte[] unknownFlag = (byte[])file.Clone();
            unknownFlag[10] |= 0x02;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(unknownFlag); });
            byte[] reserved = (byte[])file.Clone();
            reserved[11] = 1;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(reserved); });
            byte[] unknownKdf = (byte[])file.Clone();
            unknownKdf[8] = 3;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(unknownKdf); });
            byte[] future = (byte[])file.Clone();
            future[6] = 3;
            ExpectVaultError(VaultError.UnsupportedVersion, delegate { VaultFormat.ParseHeader(future); });

            // Оборванный файл формата 2.
            ExpectVaultError(VaultError.BadFormat, delegate { VaultFormat.ParseHeader(Slice(file, 0, 68 + 15)); });

            Check(Argon2id.DefaultMemoryKiB >= 19456 && Argon2id.DefaultPasses >= 2, "default Argon2id parameters are not below the OWASP minimum");
        }

        private static void SessionArgon2()
        {
            string path = NewVaultPath("argon2");
            using (VaultSession session = VaultSession.Create(path, Password))
            {
                KdfParameters protection = session.Protection;
                Check(protection.IsArgon2 && protection.MemoryKiB == 64 * 1024 && protection.Iterations == 3 && protection.Parallelism == 4 && !session.UsesKeyFile,
                    "a new vault uses Argon2id with the recommended parameters");
                session.Data.AddEntry(null, "user", "pass", "note");
                session.Save();
                Check(session.VerifyPassword(Password) && !session.VerifyPassword(Password + "x"), "password check");
            }

            byte[] raw = File.ReadAllBytes(path);
            Check(raw[6] == 2 && raw[8] == 2 && raw[10] == 0, "format version 2, Argon2id, no key file");
            VaultHeader peeked = VaultSession.Peek(path);
            Check(peeked != null && peeked.Kdf.IsArgon2 && !peeked.Kdf.KeyFile, "the header can be read without the password");
            Check(VaultSession.Peek(path + ".missing") == null, "no header for a missing file");

            using (VaultSession reopened = VaultSession.Open(path, Password))
            {
                Check(reopened.Data.Entries.Count == 1 && reopened.Data.Entries[0].Password == "pass", "data survives");
            }
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password + "x"); });

            // Хранилище прежнего формата остаётся прежним, пока его не попросят улучшить.
            string oldPath = NewVaultPath("argon2-old");
            using (VaultSession old = VaultSession.Create(oldPath, Password, FastIterations))
            {
                old.Data.AddEntry(null, "user", "pass", "note");
                old.Save();
                Check(!old.Protection.IsArgon2 && File.ReadAllBytes(oldPath)[6] == 1, "an old vault is still written in format 1");

                // Тот же пароль, новая защита: так хранилище переводится на Argon2id.
                old.ChangeProtection(Password, false, null);
                Check(old.Protection.IsArgon2 && File.ReadAllBytes(oldPath)[6] == 2, "and can be moved to Argon2id on request");
            }
            using (VaultSession upgraded = VaultSession.Open(oldPath, Password))
            {
                Check(upgraded.Data.Entries.Count == 1, "the upgraded vault opens with the same password");
            }
        }

        private static void SessionKeyFile()
        {
            string path = NewVaultPath("keyfile");
            string backup = VaultSession.BackupPath(path);
            byte[] keyFile = VaultFormat.NewKeyFile();
            byte[] otherFile = VaultFormat.NewKeyFile();
            Check(keyFile.Length == 64 && !SameBytes(keyFile, otherFile), "a new key file is 64 random bytes");

            using (VaultSession session = VaultSession.Create(path, Password, keyFile))
            {
                Check(session.UsesKeyFile && session.Protection.KeyFile, "the vault needs its key file");
                session.Data.AddEntry(null, "user", "pass", "note");
                session.Save();
                Check(session.VerifyPassword(Password) && !session.VerifyPassword("wrong"), "the password is checked together with the key file");
            }
            Check(File.ReadAllBytes(path)[10] == 1 && VaultSession.Peek(path).Kdf.KeyFile, "the header says that a key file is needed");

            ExpectVaultError(VaultError.KeyFileRequired, delegate { VaultSession.Open(path, Password); });
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password, otherFile); });
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password + "x", keyFile); });

            using (VaultSession session = VaultSession.Open(path, Password, keyFile))
            {
                Check(session.Data.Entries.Count == 1, "password and key file together open the vault");

                // Смена пароля оставляет ключевой файл прежним.
                session.ChangePassword("new password 1");
            }
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, Password, keyFile); });
            ExpectVaultError(VaultError.KeyFileRequired, delegate { VaultSession.Open(path, "new password 1"); });
            ExpectVaultError(VaultError.KeyFileRequired, delegate { VaultSession.Open(backup, "new password 1"); });

            using (VaultSession session = VaultSession.Open(path, "new password 1", keyFile))
            {
                // Другой ключевой файл.
                session.ChangeProtection("new password 1", true, otherFile);
            }
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(path, "new password 1", keyFile); });
            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(backup, "new password 1", keyFile); });

            using (VaultSession session = VaultSession.Open(path, "new password 1", otherFile))
            {
                // Отказ от ключевого файла.
                session.ChangeProtection("new password 1", false, null);
                Check(!session.UsesKeyFile, "the key file is no longer needed");
            }
            using (VaultSession session = VaultSession.Open(path, "new password 1"))
            {
                Check(session.Data.Entries.Count == 1 && File.ReadAllBytes(path)[10] == 0, "the vault opens with the password alone");
            }
            // Лишний ключевой файл при открытии не мешает.
            VaultSession.Open(path, "new password 1", keyFile).Dispose();

            // Ключевой файл добавляется к хранилищу прежнего формата.
            string oldPath = NewVaultPath("keyfile-old");
            using (VaultSession old = VaultSession.Create(oldPath, Password, FastIterations))
            {
                old.ChangeProtection(Password, true, keyFile);
                Check(old.UsesKeyFile && old.Protection.IsArgon2, "an old vault gets a key file and Argon2id at once");
            }
            ExpectVaultError(VaultError.KeyFileRequired, delegate { VaultSession.Open(oldPath, Password); });
            VaultSession.Open(oldPath, Password, keyFile).Dispose();

            // Чтение ключевого файла с диска.
            string keyPath = Path.Combine(workDir, "test.key");
            File.WriteAllBytes(keyPath, keyFile);
            Equal(keyFile, VaultSession.ReadKeyFile(keyPath));
            File.WriteAllBytes(keyPath, new byte[0]);
            ExpectVaultError(VaultError.Io, delegate { VaultSession.ReadKeyFile(keyPath); });
            File.Delete(keyPath);
            ExpectVaultError(VaultError.Io, delegate { VaultSession.ReadKeyFile(keyPath); });
        }

        // ---------- Одноразовые коды ----------

        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private static void TotpKnownAnswers()
        {
            // Приложение B из RFC 6238: восемь цифр, шаг 30 секунд.
            long[] times = { 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 };
            string[] sha1 = { "94287082", "07081804", "14050471", "89005924", "69279037", "65353130" };
            string[] sha256 = { "46119246", "68084774", "67062674", "91819424", "90698825", "77737706" };
            string[] sha512 = { "90693936", "25091201", "99943326", "93441116", "38618901", "47863826" };

            for (int i = 0; i < times.Length; i++)
            {
                DateTime moment = Epoch.AddSeconds(times[i]);
                Check(Totp.Code(TestKey("SHA1", 20), moment) == sha1[i], "SHA1 at " + times[i]);
                Check(Totp.Code(TestKey("SHA256", 32), moment) == sha256[i], "SHA256 at " + times[i]);
                Check(Totp.Code(TestKey("SHA512", 64), moment) == sha512[i], "SHA512 at " + times[i]);
            }

            // Обычные шесть цифр и ключ в Base32 — так его показывают сайты.
            TotpKey key = Totp.Parse("JBSWY3DPEHPK3PXP");
            Check(key != null && key.Digits == 6 && key.Period == 30 && key.Algorithm == "SHA1", "defaults of a plain key");
            Check(Totp.Code(key, Epoch) == "282760", "code at the epoch: " + Totp.Code(key, Epoch));
            Check(Totp.Code(key, Epoch.AddSeconds(1700000000)) == "324550", "code in 2023");
            Check(Totp.Code(key, Epoch.AddSeconds(29)) == "282760" && Totp.Code(key, Epoch.AddSeconds(30)) != "282760", "the code changes every 30 seconds");
            Check(Totp.SecondsLeft(key, Epoch) == 30 && Totp.SecondsLeft(key, Epoch.AddSeconds(29)) == 1 && Totp.SecondsLeft(key, Epoch.AddSeconds(45)) == 15, "seconds left");
            Check(Totp.Readable("282760") == "282 760" && Totp.Readable("94287082") == "9428 7082", "readable form");
        }

        private static TotpKey TestKey(string algorithm, int length)
        {
            var key = new TotpKey();
            key.Secret = Ascii("1234567890123456789012345678901234567890123456789012345678901234".Substring(0, length));
            key.Digits = 8;
            key.Algorithm = algorithm;
            return key;
        }

        private static void TotpKeyFormats()
        {
            // Base32 по RFC 4648.
            string[] plain = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
            string[] encoded = { "", "MY======", "MZXQ====", "MZXW6===", "MZXW6YQ=", "MZXW6YTB", "MZXW6YTBOI======" };
            for (int i = 0; i < plain.Length; i++)
            {
                Equal(Ascii(plain[i]), Totp.Base32Decode(encoded[i]));
            }
            Equal(Ascii("12345678901234567890"), Totp.Base32Decode("gezd gnbv-gy3t qojq GEZD GNBV GY3T QOJQ"));
            Check(Totp.Base32Decode("MZXW6YTB0") == null && Totp.Base32Decode("MZ=XW") == null && Totp.Base32Decode("привет") == null,
                "foreign characters are rejected");

            TotpKey spaced = Totp.Parse("  jbsw y3dp ehpk 3pxp  ");
            Check(spaced != null && Totp.Code(spaced, Epoch) == "282760", "spaces and case do not matter");

            TotpKey link = Totp.Parse("otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&algorithm=SHA1&digits=8&period=30");
            Check(link != null && link.Digits == 8 && Totp.Code(link, Epoch.AddSeconds(59)) == "94287082", "otpauth link");

            TotpKey sha256 = Totp.Parse("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&algorithm=sha-256&digits=8");
            Check(sha256 != null && sha256.Algorithm == "SHA256" && Totp.Code(sha256, Epoch.AddSeconds(59)) == "46119246", "link with SHA-256");

            TotpKey slow = Totp.Parse("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP&period=60");
            Check(slow != null && slow.Period == 60 && Totp.Code(slow, Epoch.AddSeconds(59)) == Totp.Code(slow, Epoch) &&
                  Totp.Code(slow, Epoch.AddSeconds(60)) != Totp.Code(slow, Epoch), "link with a 60-second period");

            Check(Totp.Parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1") == null, "counter-based codes are not supported");
            Check(Totp.Parse("otpauth://totp/x?issuer=Example") == null, "a link without a secret");
            Check(Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=12") == null &&
                  Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0") == null &&
                  Totp.Parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5") == null, "unsupported parameters");
            Check(Totp.Parse("") == null && Totp.Parse(null) == null && Totp.Parse("ABC") == null &&
                  Totp.Parse("не ключ") == null && Totp.Parse("hello world!") == null, "garbage is rejected");
        }

        // ---------- Модель: возможности версии 3 ----------

        private static void ModelWebsiteAndTotp()
        {
            VaultData data = VaultData.CreateEmpty();
            var fields = new EntryFields();
            fields.Login = "alice";
            fields.Password = "p1";
            fields.Description = "Почта";
            fields.Url = "  https://mail.example.com/login  ";
            fields.Totp = " JBSW Y3DP EHPK 3PXP ";
            Entry entry = data.AddEntry(fields);
            Check(entry.Url == "https://mail.example.com/login" && entry.Totp == "JBSW Y3DP EHPK 3PXP", "optional fields are trimmed");

            Entry plain = data.AddEntry(null, "bob", "p2", "Без сайта");
            Check(plain.Url == null && plain.Totp == null, "optional fields are absent by default");

            fields.Totp = "это не ключ";
            ExpectValidation(delegate { data.AddEntry(fields); });
            fields.Totp = null;
            fields.Url = new string('x', VaultData.MaxUrlLength + 1);
            ExpectValidation(delegate { data.AddEntry(fields); });
            Check(data.Entries.Count == 2, "invalid entries are not added");

            // Прежний вызов без новых полей их не стирает.
            Check(data.UpdateEntry(entry.Id, null, "alice", "p1", "Почта рабочая"), "an update through the short call");
            Check(entry.Url == "https://mail.example.com/login" && entry.Totp != null, "the short call keeps the website and the key");

            var changed = new EntryFields();
            changed.Login = "alice";
            changed.Password = "p1";
            changed.Description = "Почта рабочая";
            changed.Url = "mail.example.com";
            changed.Totp = "";
            Check(data.UpdateEntry(entry.Id, changed), "website and key are updated");
            Check(entry.Url == "mail.example.com" && entry.Totp == null, "an empty key removes it");
            Check(!data.UpdateEntry(entry.Id, changed), "the same values again are not a change");

            Check(data.Query(GroupFilter.All, "MAIL.example").Count == 1 && data.Query(GroupFilter.All, "example bob").Count == 0,
                "search looks into the website");

            VaultData copy = VaultData.FromJson(data.ToJson());
            Entry restored = copy.FindEntry(entry.Id);
            Check(copy.Version == 3 && restored.Url == "mail.example.com" && restored.Totp == null, "the website survives a round trip, structure version is 3");
            string json = Encoding.UTF8.GetString(data.ToJson());
            Check(json.Contains("\"url\":\"mail.example.com\"") && !json.Contains("\"totp\""), "empty optional fields are not written: " + json);
        }

        private static void ModelPasswordHistory()
        {
            VaultData data = VaultData.CreateEmpty();
            Entry entry = data.AddEntry(null, "user", "first", "Сервис");
            Check(entry.History == null, "no history at the start");

            data.UpdateEntry(entry.Id, null, "user", "first", "Сервис — описание изменено");
            Check(entry.History == null, "editing other fields does not add history");

            data.UpdateEntry(entry.Id, null, "user", "second", "Сервис");
            data.UpdateEntry(entry.Id, null, "user", "third", "Сервис");
            Check(entry.History != null && entry.History.Count == 2, "two previous passwords");
            Check(entry.History[0].Password == "second" && entry.History[1].Password == "first", "newest first");
            DateTime replaced;
            Check(VaultData.TryParseUtc(entry.History[0].Replaced, out replaced), "the time of the replacement is recorded");

            // Пустой пароль не запоминается.
            Entry empty = data.AddEntry(null, "nobody", "", "Без пароля");
            data.UpdateEntry(empty.Id, null, "nobody", "now set", "Без пароля");
            Check(empty.History == null, "an empty previous password is not kept");

            for (int i = 0; i < VaultData.MaxHistory + 5; i++)
            {
                data.UpdateEntry(entry.Id, null, "user", "password " + i, "Сервис");
            }
            Check(entry.History.Count == VaultData.MaxHistory, "history is limited: " + entry.History.Count);
            Check(entry.History[0].Password == "password " + (VaultData.MaxHistory + 3), "the latest replaced password is first");

            VaultData copy = VaultData.FromJson(data.ToJson());
            Check(copy.Version == 3 && copy.FindEntry(entry.Id).History.Count == VaultData.MaxHistory, "history survives a round trip");

            Check(data.ClearHistory(entry.Id) && entry.History == null && !data.ClearHistory(entry.Id), "history can be cleared");
        }

        private static void ModelTrash()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group projects = data.AddGroup("Проекты", work.Id);
            Entry a = data.AddEntry(work.Id, "a", "1", "A");
            Entry b = data.AddEntry(projects.Id, "b", "2", "B");
            Entry c = data.AddEntry(null, "c", "3", "C");

            Check(data.TrashEntries(new[] { a.Id, b.Id, "nope" }) == 2, "two entries go to the trash");
            Check(a.IsDeleted && b.IsDeleted && !c.IsDeleted, "trash marks");
            Check(data.Entries.Count == 3 && data.LiveCount == 1 && data.TrashCount == 2, "entries stay in the vault: counts");
            Check(data.TrashEntries(new[] { a.Id }) == 0, "already in the trash");

            // Удалённое не видно нигде, кроме корзины.
            Check(data.Query(GroupFilter.All, null).Count == 1 && data.Query(GroupFilter.ForGroup(work.Id), null).Count == 0,
                "the lists do not show deleted entries");
            Check(data.Query(GroupFilter.All, "a").Count == 0, "search does not find deleted entries");
            Check(data.Query(GroupFilter.Trash, null).Count == 2 && data.Query(GroupFilter.Trash, "b").Count == 1, "the trash shows them and can be searched");
            int ungrouped;
            Dictionary<string, int> counts = data.CountByGroup(out ungrouped);
            Check(counts[work.Id] == 0 && counts[projects.Id] == 0 && ungrouped == 1 && data.CountInBranch(work.Id) == 0, "counters skip deleted entries");
            Check(data.MoveEntries(new[] { a.Id }, null) == 0 && a.GroupId == work.Id, "deleted entries cannot be moved");

            // Восстановление возвращает на прежнее место.
            Check(data.RestoreEntries(new[] { a.Id, c.Id }) == 1 && !a.IsDeleted && a.GroupId == work.Id, "restore");

            // Группа удалена, пока запись лежит в корзине: после восстановления запись окажется уровнем выше.
            Check(data.DeleteGroup(projects.Id) == 0, "no live entries were in the deleted group");
            Check(b.GroupId == work.Id, "the deleted entry follows the entries of its group");
            data.RestoreEntries(new[] { b.Id });
            Check(data.Query(GroupFilter.ForGroup(work.Id), null).Count == 2, "restored into the parent group");

            // Окончательное удаление оставляет следы: группа «Проекты» и две записи.
            data.TrashEntries(new[] { a.Id, b.Id });
            Check(data.DeleteEntries(new[] { a.Id }) == 1 && data.FindEntry(a.Id) == null, "permanent delete of one entry");
            Check(data.EmptyTrash() == 1 && data.Entries.Count == 1 && data.TrashCount == 0, "empty the trash");
            Check(data.Removed != null && data.Removed.Count == 3, "permanent deletions leave tombstones: " + (data.Removed == null ? 0 : data.Removed.Count));

            // Срок хранения.
            Entry old = data.AddEntry(null, "old", "", "Старая");
            Entry recent = data.AddEntry(null, "recent", "", "Недавняя");
            data.TrashEntries(new[] { old.Id, recent.Id });
            old.Deleted = "2026-01-01T00:00:00Z";
            recent.Deleted = "2026-01-25T00:00:00Z";
            DateTime now = new DateTime(2026, 1, 31, 0, 0, 0, DateTimeKind.Utc);
            Check(data.PurgeTrash(VaultData.TrashDays, now) == 1 && data.FindEntry(old.Id) == null && data.FindEntry(recent.Id) != null,
                "entries older than the limit are purged");
            Check(data.PurgeTrash(VaultData.TrashDays, now) == 0, "nothing more to purge");

            VaultData copy = VaultData.FromJson(data.ToJson());
            Check(copy.Version == 3 && copy.TrashCount == 1 && copy.FindEntry(recent.Id).IsDeleted, "the trash survives a round trip");
            Check(copy.Removed != null && copy.Removed.Count == data.Removed.Count, "tombstones survive a round trip");
        }

        private static void ModelSettings()
        {
            VaultData data = VaultData.CreateEmpty();
            VaultSettings defaults = data.EffectiveSettings;
            Check(data.Settings == null && defaults.AutoLockMinutes == 5 && defaults.ClipboardSeconds == 30 && defaults.PasswordLength == 20, "defaults");
            Check(defaults.PasswordUpper && defaults.PasswordLower && defaults.PasswordDigits && defaults.PasswordSymbols &&
                  defaults.PasswordNoLookAlikes && defaults.AutoTypeEnter && defaults.Language == null, "default switches");

            Check(!data.UpdateSettings(defaults) && data.Settings == null, "saving the defaults stores nothing");
            Check(VaultData.FromJson(data.ToJson()).Version == 1, "and does not raise the structure version");

            VaultSettings custom = data.EffectiveSettings;
            custom.AutoLockMinutes = 15;
            custom.Language = "en";
            custom.PasswordSymbols = false;
            Check(data.UpdateSettings(custom) && data.Settings != null, "changed settings are stored");
            Check(!data.UpdateSettings(custom), "the same settings again are not a change");
            custom.AutoLockMinutes = 99;
            Check(data.EffectiveSettings.AutoLockMinutes == 15, "the stored settings are a copy");

            VaultData copy = VaultData.FromJson(data.ToJson());
            VaultSettings restored = copy.EffectiveSettings;
            Check(copy.Version == 3 && restored.AutoLockMinutes == 15 && restored.Language == "en" && !restored.PasswordSymbols && restored.PasswordUpper,
                "settings survive a round trip");

            // Значения из чужого или испорченного файла приводятся к допустимым.
            VaultData messy = FromJsonText("{\"version\":3,\"groups\":[],\"entries\":[],\"settings\":{\"language\":\"xx\",\"autoLockMinutes\":-5,\"clipboardSeconds\":100000,\"passwordLength\":1}}");
            VaultSettings fixedUp = messy.EffectiveSettings;
            Check(fixedUp.Language == null && fixedUp.AutoLockMinutes == 0 && fixedUp.ClipboardSeconds == VaultSettings.MaxClipboardSeconds &&
                  fixedUp.PasswordLength == VaultSettings.MinPasswordLength, "out-of-range values are clamped");
            Check(fixedUp.PasswordUpper && fixedUp.PasswordLower && fixedUp.PasswordDigits, "some character classes always stay enabled");
        }

        private static void ModelVersion3()
        {
            // Служебные отметки (время изменения групп, следы удалённого) версию не повышают.
            VaultData data = VaultData.CreateEmpty();
            Group group = data.AddGroup("Работа");
            Group other = data.AddGroup("Лишняя");
            Entry entry = data.AddEntry(group.Id, "a", "1", "A");
            Entry gone = data.AddEntry(null, "b", "2", "B");
            data.DeleteGroup(other.Id);
            data.DeleteEntries(new[] { gone.Id });
            Check(group.Changed != null && data.Removed != null && data.Removed.Count == 2, "service marks are present");
            VaultData copy = VaultData.FromJson(data.ToJson());
            Check(copy.Version == 1, "a vault without the new features keeps structure version 1: " + copy.Version);
            Check(copy.Removed != null && copy.Removed.Count == 2 && copy.Groups[0].Changed == group.Changed, "the marks are kept");

            // Вложенные группы — версия 2, новые поля записей — версия 3.
            data.AddGroup("Проекты", group.Id);
            Check(VaultData.FromJson(data.ToJson()).Version == 2, "nested groups need version 2");
            data.TrashEntries(new[] { entry.Id });
            Check(VaultData.FromJson(data.ToJson()).Version == 3, "the trash needs version 3");
            data.RestoreEntries(new[] { entry.Id });
            Check(VaultData.FromJson(data.ToJson()).Version == 2, "and an empty trash does not");

            // Файл от прежней версии программы читается как раньше.
            VaultData old = FromJsonText("{\"version\":2,\"groups\":[{\"id\":\"g1\",\"name\":\"A\"},{\"id\":\"g2\",\"name\":\"B\",\"parentId\":\"g1\"}]," +
                                         "\"entries\":[{\"id\":\"e1\",\"groupId\":\"g2\",\"login\":\"l\",\"password\":\"p\",\"description\":\"d\"}]}");
            Entry first = old.Entries[0];
            Check(first.Url == null && first.Totp == null && first.History == null && !first.IsDeleted && old.Settings == null && old.Removed == null,
                "the new fields are simply absent in an old file");
            Check(old.LiveCount == 1 && old.EffectiveSettings.AutoLockMinutes == 5, "an old file works with the defaults");
        }

        // ---------- Объединение копий ----------

        /// <summary>Вторая копия хранилища — как если бы файл открыли на другом компьютере.</summary>
        private static VaultData CopyOf(VaultData data)
        {
            return VaultData.FromJson(data.ToJson());
        }

        /// <summary>Сдвигает время изменения: копии в тестах меняются «в разное время», а не в одну секунду.</summary>
        private static void Touch(Entry entry, string when)
        {
            entry.Changed = when;
            entry.Modified = when;
        }

        /// <summary>Объединяет копии друг с другом и проверяет, что обе пришли к одному и тому же.</summary>
        private static void MergeBothWays(VaultData a, VaultData b, string what)
        {
            VaultData beforeA = CopyOf(a);
            a.Merge(b);
            b.Merge(beforeA);
            Check(a.ContentEquals(b), what + ": both copies end up the same");

            // Повторное объединение ничего не меняет.
            Check(!a.Merge(CopyOf(b)).Changed && !b.Merge(CopyOf(a)).Changed && a.ContentEquals(b), what + ": merging again changes nothing");
        }

        private static void MergeAdditionsAndEdits()
        {
            VaultData a = VaultData.CreateEmpty();
            Group work = a.AddGroup("Работа");
            Entry shared = a.AddEntry(work.Id, "user", "old-password", "Общая запись");
            Entry untouched = a.AddEntry(null, "same", "same", "Не менялась");
            Touch(shared, "2026-01-01T10:00:00Z");
            VaultData b = CopyOf(a);
            Check(a.ContentEquals(b) && !a.Merge(CopyOf(b)).Changed, "identical copies: nothing to merge");

            // В каждой копии появляется своя запись.
            Entry onlyA = a.AddEntry(null, "a", "pa", "Только в первой");
            Entry onlyB = b.AddEntry(work.Id, "b", "pb", "Только во второй");

            // Общую запись меняют обе стороны; вторая — позже.
            a.UpdateEntry(shared.Id, work.Id, "user", "password-from-a", "Общая запись");
            Touch(a.FindEntry(shared.Id), "2026-01-02T10:00:00Z");
            b.UpdateEntry(shared.Id, null, "user-b", "password-from-b", "Общая запись, вторая копия");
            Touch(b.FindEntry(shared.Id), "2026-01-03T10:00:00Z");

            VaultData beforeA = CopyOf(a);
            MergeResult result = a.Merge(b);
            Check(result.EntriesAdded == 1 && result.EntriesUpdated == 1 && result.EntriesRemoved == 0 && result.Changed, "what changed in the first copy");
            Check(a.Entries.Count == 4 && a.FindEntry(onlyA.Id) != null && a.FindEntry(onlyB.Id) != null, "entries of both copies are present");
            Check(a.FindEntry(onlyB.Id).GroupId == work.Id && a.FindEntry(onlyB.Id).Password == "pb", "the added entry keeps its fields");

            Entry merged = a.FindEntry(shared.Id);
            Check(merged.Password == "password-from-b" && merged.Login == "user-b" && merged.GroupId == null && merged.Description == "Общая запись, вторая копия",
                "the later edit wins as a whole");
            var kept = new List<string>();
            foreach (PasswordRecord record in merged.History) kept.Add(record.Password);
            Check(kept.Contains("password-from-a") && kept.Contains("old-password"), "the password of the losing side is kept in the history: " + string.Join(", ", kept.ToArray()));
            Check(a.FindEntry(untouched.Id).Password == "same", "untouched entries stay as they are");

            MergeResult back = b.Merge(beforeA);
            Check(back.EntriesAdded == 1 && back.EntriesUpdated == 0, "the second copy only gains the entry it lacked");
            Check(a.ContentEquals(b), "both copies end up the same");
            Check(b.FindEntry(shared.Id).History != null && b.FindEntry(shared.Id).History.Count == merged.History.Count, "including the password history");

            // Итог в словах.
            Check(result.Describe().Contains("добавлено: 1") && result.Describe().Contains("изменено: 1"), "summary: " + result.Describe());
            Check(new MergeResult().Describe() == "изменений нет", "summary of an empty merge");

            // Правка в одну и ту же секунду: выигрывает одна и та же версия, с какой стороны ни объединяй.
            VaultData c = VaultData.CreateEmpty();
            Entry tie = c.AddEntry(null, "tie", "p0", "Одновременно");
            VaultData d = CopyOf(c);
            c.UpdateEntry(tie.Id, null, "tie", "p-from-c", "Одновременно");
            d.UpdateEntry(tie.Id, null, "tie", "p-from-d", "Одновременно");
            Touch(c.FindEntry(tie.Id), "2026-02-01T00:00:00Z");
            Touch(d.FindEntry(tie.Id), "2026-02-01T00:00:00Z");
            MergeBothWays(c, d, "same-second edits");
        }

        private static void MergeDeletions()
        {
            VaultData a = VaultData.CreateEmpty();
            Entry trashed = a.AddEntry(null, "t", "1", "В корзину");
            Entry purged = a.AddEntry(null, "p", "2", "Навсегда");
            Entry edited = a.AddEntry(null, "e", "3", "Удалена там, изменена здесь");
            Entry stays = a.AddEntry(null, "s", "4", "Остаётся");
            foreach (Entry entry in a.Entries) Touch(entry, "2026-01-01T00:00:00Z");
            VaultData b = CopyOf(a);

            // Вторая копия: одну запись в корзину, две стёрты окончательно.
            b.TrashEntries(new[] { trashed.Id });
            b.FindEntry(trashed.Id).Changed = "2026-01-05T00:00:00Z";
            b.DeleteEntries(new[] { purged.Id, edited.Id });
            foreach (Tombstone tombstone in b.Removed) tombstone.When = "2026-01-05T00:00:00Z";

            // Первая копия: одну из стёртых там записей позже изменили.
            a.UpdateEntry(edited.Id, null, "e", "new-password", "Удалена там, изменена здесь");
            Touch(a.FindEntry(edited.Id), "2026-01-06T00:00:00Z");

            VaultData beforeA = CopyOf(a);
            MergeResult result = a.Merge(b);
            Check(result.EntriesRemoved == 1 && a.FindEntry(purged.Id) == null, "an entry deleted for good in the other copy is deleted here");
            Check(a.FindEntry(trashed.Id) != null && a.FindEntry(trashed.Id).IsDeleted, "an entry trashed in the other copy is in the trash here");
            Check(a.FindEntry(edited.Id) != null && a.FindEntry(edited.Id).Password == "new-password", "an edit made after the deletion wins: the entry survives");
            Check(a.FindEntry(stays.Id) != null && a.LiveCount == 2 && a.TrashCount == 1, "counts after the merge");

            b.Merge(beforeA);
            Check(b.FindEntry(edited.Id) != null && b.FindEntry(edited.Id).Password == "new-password", "the surviving entry returns to the copy that deleted it");
            Check(a.ContentEquals(b), "both copies end up the same");

            // Удалённое не возвращается из третьей, давно не обновлявшейся копии.
            VaultData stale = VaultData.CreateEmpty();
            stale.Entries.Add(CloneForTest(beforeA.FindEntry(purged.Id)));
            Check(!a.Merge(stale).Changed && a.FindEntry(purged.Id) == null, "a stale copy does not bring a deleted entry back");

            // Восстановление из корзины позже удаления — тоже изменение, и оно побеждает.
            VaultData c = CopyOf(a);
            c.RestoreEntries(new[] { trashed.Id });
            c.FindEntry(trashed.Id).Changed = "2026-01-07T00:00:00Z";
            MergeBothWays(a, c, "restore from the trash");
            Check(!a.FindEntry(trashed.Id).IsDeleted, "the restored entry is restored in both copies");
        }

        private static Entry CloneForTest(Entry source)
        {
            var copy = new Entry();
            copy.Id = source.Id;
            copy.GroupId = source.GroupId;
            copy.Login = source.Login;
            copy.Password = source.Password;
            copy.Description = source.Description;
            copy.Created = source.Created;
            copy.Modified = source.Modified;
            copy.Changed = source.Changed;
            return copy;
        }

        private static void MergeGroups()
        {
            VaultData a = VaultData.CreateEmpty();
            Group work = a.AddGroup("Работа");
            Group servers = a.AddGroup("Серверы", work.Id);
            Group home = a.AddGroup("Дом");
            Group doomed = a.AddGroup("Лишняя");
            Entry inServers = a.AddEntry(servers.Id, "s", "1", "На сервере");
            Entry inDoomed = a.AddEntry(doomed.Id, "d", "2", "В лишней");
            foreach (Group group in a.Groups) group.Changed = "2026-01-01T00:00:00Z";
            foreach (Entry entry in a.Entries) Touch(entry, "2026-01-01T00:00:00Z");
            VaultData b = CopyOf(a);

            // Первая копия переименовывает группу и создаёт новую.
            a.RenameGroup(work.Id, "Работа и проекты");
            a.FindGroup(work.Id).Changed = "2026-01-02T00:00:00Z";
            Group added = a.AddGroup("Банки");

            // Вторая переносит подгруппу, удаляет группу с записью и тоже создаёт «Банки».
            b.MoveGroup(servers.Id, home.Id);
            b.FindGroup(servers.Id).Changed = "2026-01-03T00:00:00Z";
            b.DeleteGroup(doomed.Id);
            foreach (Tombstone tombstone in b.Removed) tombstone.When = "2026-01-03T00:00:00Z";
            b.FindEntry(inDoomed.Id).Changed = "2026-01-03T00:00:00Z";
            Group addedToo = b.AddGroup("банки");
            Entry inBanks = b.AddEntry(addedToo.Id, "bank", "3", "Счёт");

            MergeBothWays(a, b, "groups");

            Check(a.FindGroup(work.Id).Name == "Работа и проекты", "the rename from the first copy");
            Check(a.FindGroup(servers.Id).ParentId == home.Id && a.GroupPath(a.FindEntry(inServers.Id).GroupId) == "Дом / Серверы", "the move from the second copy");
            Check(a.FindGroup(doomed.Id) == null && a.FindEntry(inDoomed.Id) != null && a.FindEntry(inDoomed.Id).GroupId == null,
                "the deleted group is gone, its entry stays");

            // Две группы «Банки», созданные порознь, становятся одной; запись остаётся в ней.
            int banks = 0;
            foreach (Group group in a.Groups)
            {
                if (string.Equals(group.Name, "Банки", StringComparison.OrdinalIgnoreCase)) banks++;
            }
            Check(banks == 1 && a.Groups.Count == 4, "same-named groups created apart become one: " + a.Groups.Count + " groups");
            Group bank = a.FindGroup(a.FindEntry(inBanks.Id).GroupId);
            Check(bank != null && string.Equals(bank.Name, "Банки", StringComparison.OrdinalIgnoreCase), "the entry is in the surviving group");
            Check(string.CompareOrdinal(bank.Id, bank.Id == added.Id ? addedToo.Id : added.Id) < 0, "the group with the smaller identifier survives");

            // Запись, которую в другой копии успели изменить, а здесь её группу удалили, не теряется.
            VaultData c = CopyOf(a);
            VaultData d = CopyOf(a);
            c.DeleteGroup(home.Id);
            foreach (Tombstone tombstone in c.Removed) tombstone.When = "2026-02-01T00:00:00Z";
            c.FindEntry(inServers.Id).Changed = "2026-02-01T00:00:00Z";
            d.UpdateEntry(inServers.Id, servers.Id, "s", "newer", "На сервере");
            Touch(d.FindEntry(inServers.Id), "2026-02-02T00:00:00Z");
            MergeBothWays(c, d, "an entry edited while its group was deleted");
            Check(c.FindGroup(home.Id) == null && c.FindGroup(servers.Id) == null, "the deleted branch stays deleted");
            Check(c.FindEntry(inServers.Id).Password == "newer" && c.FindEntry(inServers.Id).GroupId == null, "the newer entry survives, one level up");

            // Встречные переносы (А в Б и Б в А) не зацикливают дерево.
            VaultData e = VaultData.CreateEmpty();
            Group first = e.AddGroup("Первая");
            Group second = e.AddGroup("Вторая");
            first.Changed = second.Changed = "2026-01-01T00:00:00Z";
            VaultData f = CopyOf(e);
            e.MoveGroup(first.Id, second.Id);
            e.FindGroup(first.Id).Changed = "2026-03-01T00:00:00Z";
            f.MoveGroup(second.Id, first.Id);
            f.FindGroup(second.Id).Changed = "2026-03-02T00:00:00Z";
            MergeBothWays(e, f, "opposite moves");
            Check(e.TreeOrder(string.CompareOrdinal).Count == 2, "both groups are still reachable in the tree");
            Check(e.FindGroup(first.Id).ParentId == null || e.FindGroup(second.Id).ParentId == null, "the ring is broken");
        }

        private static void MergeSettingsAndSymmetry()
        {
            VaultData a = VaultData.CreateEmpty();
            a.AddEntry(null, "u", "p", "Запись");
            VaultData b = CopyOf(a);

            VaultSettings older = a.EffectiveSettings;
            older.AutoLockMinutes = 10;
            a.UpdateSettings(older);
            a.Settings.Changed = "2026-01-01T00:00:00Z";

            VaultSettings newer = b.EffectiveSettings;
            newer.AutoLockMinutes = 30;
            newer.Language = "en";
            b.UpdateSettings(newer);
            b.Settings.Changed = "2026-01-02T00:00:00Z";

            MergeResult result = a.Merge(b);
            Check(result.SettingsUpdated && result.Changed && a.EffectiveSettings.AutoLockMinutes == 30 && a.EffectiveSettings.Language == "en", "the later settings win");
            Check(!b.Merge(a).Changed && b.EffectiveSettings.AutoLockMinutes == 30, "the copy with the later settings keeps them");
            Check(a.ContentEquals(b), "both copies end up the same");

            // Случайные правки в двух копиях: с какой стороны ни объединяй, итог один.
            var random = new Random(20261115);
            for (int round = 0; round < 40; round++)
            {
                VaultData first = VaultData.CreateEmpty();
                Group g1 = first.AddGroup("Группа 1");
                Group g2 = first.AddGroup("Группа 2");
                var ids = new List<string>();
                for (int i = 0; i < 6; i++)
                {
                    Entry entry = first.AddEntry(i % 2 == 0 ? g1.Id : null, "login" + i, "password" + i, "Запись " + i);
                    Touch(entry, "2026-01-01T00:00:00Z");
                    ids.Add(entry.Id);
                }
                g1.Changed = g2.Changed = "2026-01-01T00:00:00Z";
                VaultData second = CopyOf(first);

                foreach (VaultData copy in new[] { first, second })
                {
                    for (int step = 0; step < 5; step++)
                    {
                        string id = ids[random.Next(ids.Count)];
                        Entry entry = copy.FindEntry(id);
                        string when = "2026-02-" + (1 + random.Next(20)).ToString("00") + "T00:00:0" + random.Next(10) + "Z";
                        int action = random.Next(5);
                        if (entry == null)
                        {
                            Entry added = copy.AddEntry(null, "new", "new" + random.Next(1000), "Новая " + random.Next(1000));
                            Touch(added, when);
                        }
                        else if (action == 0)
                        {
                            copy.UpdateEntry(id, entry.GroupId, entry.Login, "changed" + random.Next(1000), entry.Description);
                            Touch(entry, when);
                        }
                        else if (action == 1)
                        {
                            bool toGroup = random.Next(2) == 0 && copy.FindGroup(g2.Id) != null;
                            copy.MoveEntries(new[] { id }, toGroup ? g2.Id : null);
                            entry.Changed = when;
                        }
                        else if (action == 2)
                        {
                            copy.TrashEntries(new[] { id });
                            entry.Changed = when;
                        }
                        else if (action == 3)
                        {
                            copy.DeleteEntries(new[] { id });
                            foreach (Tombstone tombstone in copy.Removed)
                            {
                                if (tombstone.Id == id) tombstone.When = when;
                            }
                        }
                        else if (copy.FindGroup(g2.Id) != null && random.Next(3) == 0)
                        {
                            copy.DeleteGroup(g2.Id);
                            foreach (Tombstone tombstone in copy.Removed)
                            {
                                if (tombstone.Id == g2.Id) tombstone.When = when;
                            }
                        }
                    }
                }
                MergeBothWays(first, second, "random edits, round " + round);
            }
        }

        // ---------- Один файл, открытый в двух местах ----------

        private static int foreignWrites;

        /// <summary>Записывает файл «со стороны» — как это сделала бы другая программа или облачная папка.</summary>
        private static void WriteForeign(string path, byte[] content)
        {
            File.WriteAllBytes(path, content);
            // Время изменения заведомо отличается от прежнего, даже если записи идут подряд.
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddSeconds(++foreignWrites));
        }

        /// <summary>
        /// Проверка файла, который только что изменили «со стороны». Сразу после записи файл бывает
        /// занят на мгновение (антивирус, индексатор) — тогда программа заглянула бы в него при
        /// следующей проверке; тест делает то же самое.
        /// </summary>
        private static bool ReloadChanged(VaultSession session)
        {
            for (int attempt = 0; attempt < 40; attempt++)
            {
                if (session.Reload()) return true;
                System.Threading.Thread.Sleep(50);
            }
            return false;
        }

        private static void SharedFileMerge()
        {
            string path = NewVaultPath("shared");
            using (VaultSession first = VaultSession.Create(path, Password, FastIterations))
            using (VaultSession second = VaultSession.Open(path, Password))
            {
                Check(first.TakeMerge() == null && second.TakeMerge() == null, "nothing is merged while the file is only ours");
                Check(!first.Reload() && !second.Reload(), "an unchanged file is not read again");

                // Оба «компьютера» добавляют по записи; второй сохраняет позже и не должен затереть первую.
                Entry a = first.Data.AddEntry(null, "a", "pa", "С первого компьютера");
                first.Save();
                Check(first.TakeMerge() == null, "saving over our own file merges nothing");

                Entry b = second.Data.AddEntry(null, "b", "pb", "Со второго компьютера");
                second.Save();
                MergeResult merged = second.TakeMerge();
                Check(merged != null && merged.EntriesAdded == 1 && second.Data.Entries.Count == 2 && second.Data.FindEntry(a.Id) != null,
                    "the second copy picks up the entry of the first one when it saves");
                Check(second.TakeMerge() == null, "the result is handed out once");
                using (VaultSession file = VaultSession.Open(path, Password))
                {
                    Check(file.Data.Entries.Count == 2, "the file holds the entries of both");
                }

                // Первая копия узнаёт о чужой записи при проверке файла — и ничего не пишет: в файле уже всё есть.
                byte[] before = File.ReadAllBytes(path);
                Check(ReloadChanged(first), "the first copy notices the changed file");
                merged = first.TakeMerge();
                Check(merged != null && merged.EntriesAdded == 1 && first.Data.FindEntry(b.Id) != null, "and picks up the entry of the second one");
                Equal(before, File.ReadAllBytes(path));
                Check(!first.Reload() && first.TakeMerge() == null, "a second look finds nothing new");
                Check(first.Data.ContentEquals(second.Data), "both copies hold the same");

                // Удаление тоже доходит до другой копии.
                first.Data.TrashEntries(new[] { b.Id });
                first.Data.DeleteEntries(new[] { b.Id });
                first.Save();
                Check(ReloadChanged(second), "the deletion is noticed");
                merged = second.TakeMerge();
                Check(merged.EntriesRemoved == 1 && second.Data.FindEntry(b.Id) == null && second.Data.Entries.Count == 1,
                    "an entry deleted in one copy is gone in the other");

                // Одна запись изменена в обеих копиях: остаётся поздняя правка, пароль ранней уходит в историю.
                first.Data.UpdateEntry(a.Id, null, "a", "password-of-first", "С первого компьютера");
                Touch(first.Data.FindEntry(a.Id), "2026-03-01T10:00:00Z");
                first.Save();
                second.Data.UpdateEntry(a.Id, null, "a-renamed", "password-of-second", "С первого компьютера");
                Touch(second.Data.FindEntry(a.Id), "2026-03-01T11:00:00Z");
                second.Save();
                Check(ReloadChanged(first), "the later edit is noticed");
                Entry result = first.Data.FindEntry(a.Id);
                Check(result.Login == "a-renamed" && result.Password == "password-of-second", "the later edit wins in both copies");
                bool kept = false;
                foreach (PasswordRecord record in result.History) kept |= record.Password == "password-of-first";
                Check(kept, "the password of the earlier edit is kept in the history");
                Check(first.Data.ContentEquals(second.Data), "both copies hold the same again");

                // Несколько объединений подряд складываются в один итог.
                second.Data.AddEntry(null, "c", "pc", "Третья");
                second.Save();
                ReloadChanged(first);
                second.Data.AddEntry(null, "d", "pd", "Четвёртая");
                second.Save();
                ReloadChanged(first);
                merged = first.TakeMerge();
                Check(merged.EntriesAdded == 2 && merged.EntriesUpdated == 1, "results add up until they are taken: " + merged.Describe());
            }
        }

        private static void SharedFileReload()
        {
            string path = NewVaultPath("reload");
            using (VaultSession first = VaultSession.Create(path, Password, FastIterations))
            using (VaultSession second = VaultSession.Open(path, Password))
            {
                // У второй копии есть запись, которой нет в файле: облако оставило чужую версию вместо её собственной.
                Entry mine = second.Data.AddEntry(null, "second", "p2", "Есть только в памяти");
                Entry theirs = first.Data.AddEntry(null, "first", "p1", "Записана первой копией");
                first.Save();

                Check(ReloadChanged(second), "the changed file is noticed");
                Check(second.Data.Entries.Count == 2 && !second.HasUnwrittenChanges, "the copy merges the file and writes back what it lacked");
                using (VaultSession file = VaultSession.Open(path, Password))
                {
                    Check(file.Data.FindEntry(mine.Id) != null && file.Data.FindEntry(theirs.Id) != null, "the file now holds both entries");
                }

                // Первая копия подхватывает это и ничего больше не пишет: копии сошлись.
                byte[] settled = File.ReadAllBytes(path);
                Check(ReloadChanged(first) && first.Data.ContentEquals(second.Data), "the first copy catches up");
                Check(!second.Reload() && !first.Reload(), "then both stay quiet");
                Equal(settled, File.ReadAllBytes(path));

                // Упрямый сосед раз за разом возвращает в файл старую версию. Копия дописывает файл,
                // но не без конца: после нескольких попыток она ждёт обычного сохранения.
                byte[] stale = File.ReadAllBytes(path);
                Entry extra = second.Data.AddEntry(null, "extra", "p3", "Ещё одна запись");
                second.Save();
                int rewritten = 0;
                for (int round = 0; round < 6; round++)
                {
                    WriteForeign(path, stale);
                    // С пятого раза в файле лежит ровно то, что копия уже видела, — читать его заново незачем.
                    if (round < 4) Check(ReloadChanged(second), "round " + round + ": the stale file is noticed");
                    else Check(!second.Reload(), "round " + round + ": a file already seen is not merged again");
                    if (!SameBytes(stale, File.ReadAllBytes(path))) rewritten++;
                }
                Check(rewritten == 3, "the file is rewritten a limited number of times: " + rewritten);
                Check(second.HasUnwrittenChanges, "after that the copy remembers that the file lacks its changes");
                second.Save();
                Check(!second.HasUnwrittenChanges, "an ordinary save writes them");
                using (VaultSession file = VaultSession.Open(path, Password))
                {
                    Check(file.Data.FindEntry(extra.Id) != null, "and the entry is in the file");
                }
            }
        }

        private static void SharedFileConflict()
        {
            const string newPassword = "пароль, сменённый в другом месте";
            string path = NewVaultPath("conflict");
            string copyPath;
            Entry late;

            using (VaultSession first = VaultSession.Create(path, Password, FastIterations))
            using (VaultSession second = VaultSession.Open(path, Password))
            {
                first.Data.AddEntry(null, "common", "p0", "Общая запись");
                first.Save();
                ReloadChanged(second);

                // Копия того же хранилища читается тем же ключом — пароль не нужен.
                string twin = path + ".twin";
                File.Copy(path, twin);
                VaultData same = second.ReadCopy(twin);
                Check(same != null && same.Entries.Count == 1, "a copy of the same vault is read with the key of the session");

                // В другом месте сменили мастер-пароль: файл перешифрован.
                first.ChangePassword(newPassword);
                byte[] rekeyed = File.ReadAllBytes(path);

                late = second.Data.AddEntry(null, "late", "p1", "Добавлена после смены пароля");
                ExpectVaultError(VaultError.Conflict, delegate { second.Save(); });
                ExpectVaultError(VaultError.Conflict, delegate { ReloadChanged(second); });
                Equal(rekeyed, File.ReadAllBytes(path));

                // Несохранённое уходит в отдельный файл рядом, который открывается прежним паролем.
                copyPath = second.SaveConflictCopy(null);
                Check(copyPath != path && File.Exists(copyPath) && Path.GetFileName(copyPath).Contains(".conflict-") && copyPath.EndsWith(".vault"),
                    "conflict copy: " + Path.GetFileName(copyPath));
                Check(Path.GetDirectoryName(copyPath) == Path.GetDirectoryName(path), "the copy lies next to the vault");
                string another = second.SaveConflictCopy(null);
                Check(another != copyPath && File.Exists(another), "one more copy does not overwrite the first: " + Path.GetFileName(another));
                Equal(rekeyed, File.ReadAllBytes(path));
                Check(first.ReadCopy(copyPath) == null, "the copy is encrypted with the previous key: it needs its own password");
            }

            ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(copyPath, newPassword); });
            using (VaultSession current = VaultSession.Open(path, newPassword))
            using (VaultSession copy = VaultSession.Open(copyPath, Password))
            {
                Check(current.Data.FindEntry(late.Id) == null, "the vault itself lacks the late entry");
                MergeResult merged = current.Data.Merge(copy.Data);
                Check(merged.EntriesAdded == 1 && current.Data.FindEntry(late.Id) != null, "merging the copy brings it back");
                current.Save();
            }

            // Смена пароля сначала вливает то, что успели записать в другом месте.
            string rekeyPath = NewVaultPath("rekey");
            using (VaultSession first = VaultSession.Create(rekeyPath, Password, FastIterations))
            using (VaultSession second = VaultSession.Open(rekeyPath, Password))
            {
                Entry fromSecond = second.Data.AddEntry(null, "s", "p", "Записана перед самой сменой пароля");
                second.Save();
                first.ChangePassword(newPassword);
                MergeResult merged = first.TakeMerge();
                Check(first.Data.FindEntry(fromSecond.Id) != null && merged != null && merged.EntriesAdded == 1, "changing the password merges the file first");
            }
            using (VaultSession file = VaultSession.Open(rekeyPath, newPassword))
            {
                Check(file.Data.Entries.Count == 1, "nothing is lost when the password changes");
            }

            // Файл записала более новая версия программы: прочитать его нельзя, затирать — тоже.
            string newerPath = NewVaultPath("newer");
            using (VaultSession session = VaultSession.Create(newerPath, Password, FastIterations))
            {
                byte[] own = File.ReadAllBytes(newerPath);
                VaultHeader header = VaultFormat.ParseHeader(own);
                session.Data.AddEntry(null, "x", "y", "Не должна затереть чужой файл");

                byte[] newerFormat = (byte[])own.Clone();
                newerFormat[6] = 9;
                WriteForeign(newerPath, newerFormat);
                ExpectVaultError(VaultError.Conflict, delegate { session.Save(); });
                ExpectVaultError(VaultError.Conflict, delegate { ReloadChanged(session); });
                Equal(newerFormat, File.ReadAllBytes(newerPath));

                byte[] key = VaultFormat.DeriveKey(Password, header.Salt, header.Iterations);
                byte[] newerData = VaultFormat.Seal(key, header.Salt, header.Iterations, Encoding.UTF8.GetBytes("{\"version\":99,\"groups\":[],\"entries\":[]}"));
                WriteForeign(newerPath, newerData);
                ExpectVaultError(VaultError.Conflict, delegate { session.Save(); });
                Equal(newerData, File.ReadAllBytes(newerPath));
            }

            // Испорченный или недописанный файл беречь незачем: проверка его пропускает, сохранение — заменяет.
            string damagedPath = NewVaultPath("damaged");
            using (VaultSession session = VaultSession.Create(damagedPath, Password, FastIterations))
            {
                Entry kept = session.Data.AddEntry(null, "k", "v", "Уцелевшая запись");
                session.Save();
                byte[] good = File.ReadAllBytes(damagedPath);

                byte[] cut = Slice(good, 0, good.Length - 7);
                WriteForeign(damagedPath, cut);
                Check(!session.Reload() && session.TakeMerge() == null, "a truncated file is not merged");
                Equal(cut, File.ReadAllBytes(damagedPath));
                session.Save();
                using (VaultSession file = VaultSession.Open(damagedPath, Password))
                {
                    Check(file.Data.FindEntry(kept.Id) != null, "saving replaces the damaged file");
                }

                WriteForeign(damagedPath, Ascii("not a vault at all"));
                Check(!session.Reload(), "a foreign file is not merged either");
                session.Save();
                VaultSession.Open(damagedPath, Password).Dispose();

                File.Delete(damagedPath);
                Check(!session.Reload(), "a missing file is nothing to merge");
                session.Save();
                Check(File.Exists(damagedPath), "saving recreates a deleted file");
            }
        }

        // ---------- Импорт и экспорт ----------

        private static void CsvParsing()
        {
            List<string[]> rows = Csv.Parse("a,b,c\r\n1,\"two, with comma\",\"quote \"\"inside\"\"\"\r\n\"multi\nline\",,last\n");
            Check(rows.Count == 3 && rows[0].Length == 3 && rows[1].Length == 3 && rows[2].Length == 3, "three rows of three fields");
            Check(rows[1][1] == "two, with comma" && rows[1][2] == "quote \"inside\"", "commas and quotes inside quoted fields");
            Check(rows[2][0] == "multi\nline" && rows[2][1] == "" && rows[2][2] == "last", "a line break inside a field, an empty field");

            rows = Csv.Parse((char)0xFEFF + "name;password\r\n\r\nx;y\r\n\r\n");
            Check(rows.Count == 2 && rows[0][0] == "name" && rows[1][1] == "y", "byte order mark, blank lines, semicolons");

            rows = Csv.Parse("name\tpassword\nx\t\"a,b\"");
            Check(rows.Count == 2 && rows[1][1] == "a,b", "tabs, no line break at the end");

            rows = Csv.Parse("a,b\n\"\",\"\"\n");
            Check(rows.Count == 2 && rows[1].Length == 2 && rows[1][0] == "" && rows[1][1] == "", "quoted empty fields make a row");
            Check(Csv.Parse("").Count == 0 && Csv.Parse(null).Count == 0, "empty input");

            var original = new List<string[]>();
            original.Add(new[] { "plain", "with, comma", "with \"quotes\"", "multi\r\nline", " padded ", "", "semi;colon", "кириллица" });
            List<string[]> back = Csv.Parse(Csv.Write(original));
            Check(back.Count == 1 && back[0].Length == original[0].Length, "written rows read back");
            for (int i = 0; i < original[0].Length; i++)
            {
                Check(back[0][i] == original[0][i], "field " + i + " survives: [" + back[0][i] + "]");
            }
        }

        private static void ImportFormats()
        {
            // Chrome и Edge.
            ImportPlan chrome = VaultTransfer.ReadCsv(
                "name,url,username,password,note\r\n" +
                "example.com,https://example.com/login,alice,pa55,\"first line\nsecond line\"\r\n" +
                ",,,,\r\n" +
                "shop,https://shop.example/,bob,\"p,w\",\r\n");
            Check(chrome.Error == null && chrome.Entries.Count == 2 && chrome.Skipped == 1, "chrome: two entries, one empty line skipped");
            Check(chrome.Entries[0].Title == "example.com" && chrome.Entries[0].Url == "https://example.com/login" &&
                  chrome.Entries[0].Login == "alice" && chrome.Entries[0].Password == "pa55" && chrome.Entries[0].Notes == "first line\nsecond line",
                "chrome: fields of the first entry");
            Check(chrome.Entries[1].Password == "p,w" && chrome.Entries[1].Notes == "", "chrome: a comma inside a password");

            // Firefox: названия нет, много служебных столбцов.
            ImportPlan firefox = VaultTransfer.ReadCsv(
                "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n" +
                "\"https://mail.example.org\",\"carol\",\"s3cret\",,\"https://mail.example.org\",\"{6f2a}\",\"1700000000000\",\"1700000000000\",\"1700000000000\"\n");
            Check(firefox.Error == null && firefox.Entries.Count == 1, "firefox: one entry");
            Check(firefox.Entries[0].Title == "" && firefox.Entries[0].Url == "https://mail.example.org" && firefox.Entries[0].Login == "carol" &&
                  firefox.Entries[0].Password == "s3cret", "firefox: fields");

            // Bitwarden: папка, одноразовый код, защищённая заметка без пароля.
            ImportPlan bitwarden = VaultTransfer.ReadCsv(
                "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n" +
                "Social,1,login,Twitter,,,0,twitter.com,me@example.com,password123,JBSWY3DPEHPK3PXP\n" +
                ",,note,Secure Note Name,the note text,,,,,,\n");
            Check(bitwarden.Error == null && bitwarden.Entries.Count == 2, "bitwarden: two entries");
            Check(bitwarden.Entries[0].Group == "Social" && bitwarden.Entries[0].Title == "Twitter" && bitwarden.Entries[0].Url == "twitter.com" &&
                  bitwarden.Entries[0].Login == "me@example.com" && bitwarden.Entries[0].Password == "password123" &&
                  bitwarden.Entries[0].Totp == "JBSWY3DPEHPK3PXP", "bitwarden: login");
            Check(bitwarden.Entries[1].Title == "Secure Note Name" && bitwarden.Entries[1].Notes == "the note text" && bitwarden.Entries[1].Password == "",
                "bitwarden: note");

            // KeePassXC: группа путём, заголовки с прописной буквы.
            ImportPlan keepass = VaultTransfer.ReadCsv(
                "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n" +
                "\"Passwords/Internet\",\"Forum\",\"dave\",\"pw\",\"https://forum.example\",\"\",\"\",\"0\",\"2026-01-01T00:00:00Z\",\"2026-01-01T00:00:00Z\"\n");
            Check(keepass.Error == null && keepass.Entries.Count == 1 && keepass.Entries[0].Group == "Passwords/Internet" &&
                  keepass.Entries[0].Title == "Forum" && keepass.Entries[0].Login == "dave" && keepass.Entries[0].Url == "https://forum.example",
                "keepassxc: fields");

            // Непонятные файлы не импортируются вовсе.
            Check(VaultTransfer.ReadCsv("").Error != null, "an empty file");
            Check(VaultTransfer.ReadCsv("just some text\nmore text").Error != null, "a file without a password column");
            Check(VaultTransfer.ReadCsv("password\nonly").Error != null, "a password column alone is not enough");
            ImportPlan headerOnly = VaultTransfer.ReadCsv("name,password\n");
            Check(headerOnly.Error == null && headerOnly.Entries.Count == 0, "a header without rows is an empty list, not an error");

            ImportPlan tooLong = VaultTransfer.ReadCsv("name,password\nok,short\nbad," + new string('x', VaultData.MaxPasswordLength + 1) + "\n");
            Check(tooLong.Entries.Count == 1 && tooLong.Skipped == 1, "an impossible password is skipped, not cut");
        }

        private static void ImportIntoVault()
        {
            VaultData data = VaultData.CreateEmpty();
            data.AddGroup("Импорт");
            Entry own = data.AddEntry(null, "mine", "p", "Своя запись");

            ImportPlan plan = VaultTransfer.ReadCsv(
                "name,url,username,password,note,group,totp\n" +
                "Почта,mail.example.com,alice,pw1,заметка,Работа/Серверы,JBSWY3DPEHPK3PXP\n" +
                "Форум,,bob,pw2,,Работа,не ключ\n" +
                ",https://shop.example.com/cart,,pw3,,,\n" +
                "Глубоко,,deep,pw4,,a/b/c/d/e/f/g/h/i/j,\n" +
                "Без группы,,carol,pw5,,,\n");
            Check(plan.Error == null && plan.Entries.Count == 5, "five rows are read");

            ImportResult result = VaultTransfer.Import(data, plan, "Импорт");
            Check(result.Entries == 5 && result.Root.Name == "Импорт (2)" && result.Root.ParentId == null, "a new top-level group with a free name: " + result.Root.Name);
            Check(result.Groups == 9, "subgroups are created from the paths: " + result.Groups);

            Func<string, Entry> byPassword = delegate(string password)
            {
                foreach (Entry entry in data.Entries)
                {
                    if (entry.Password == password) return entry;
                }
                return null;
            };

            Entry mail = byPassword("pw1");
            Check(data.GroupPath(mail.GroupId) == "Импорт (2) / Работа / Серверы", "nested group: " + data.GroupPath(mail.GroupId));
            Check(mail.Description == "Почта\nзаметка" && mail.Url == "mail.example.com" && mail.Login == "alice" && mail.Totp == "JBSWY3DPEHPK3PXP",
                "title and note become the description, the key is kept");

            Entry forum = byPassword("pw2");
            Check(data.GroupPath(forum.GroupId) == "Импорт (2) / Работа" && forum.Totp == null && forum.Description == "Форум\nTOTP: не ключ",
                "a key that cannot be read is kept in the description: " + forum.Description);

            Entry shop = byPassword("pw3");
            Check(shop.Description == "shop.example.com" && shop.GroupId == result.Root.Id && shop.Url == "https://shop.example.com/cart",
                "an entry without a name is named after its website: " + shop.Description);

            Entry deep = byPassword("pw4");
            Check(data.DepthOf(deep.GroupId) == VaultData.MaxGroupDepth, "nesting is cut at the allowed depth: " + data.DepthOf(deep.GroupId));
            Check(byPassword("pw5").GroupId == result.Root.Id, "entries without a group go to the import group itself");

            Check(data.FindEntry(own.Id) != null && own.GroupId == null && data.LiveCount == 6, "existing entries are untouched");

            ImportResult again = VaultTransfer.Import(data, plan, "Импорт");
            Check(again.Root.Name == "Импорт (3)" && data.LiveCount == 11, "a second import gets its own group: " + again.Root.Name);
        }

        private static void ExportRoundTrip()
        {
            VaultData data = VaultData.CreateEmpty();
            Group work = data.AddGroup("Работа");
            Group servers = data.AddGroup("Серверы", work.Id);

            var fields = new EntryFields();
            fields.GroupId = servers.Id;
            fields.Login = "alice";
            fields.Password = "p,\"q\" ;";
            fields.Description = "Почта\nвторая строка\nтретья";
            fields.Url = "https://mail.example.com";
            fields.Totp = "JBSWY3DPEHPK3PXP";
            data.AddEntry(fields);
            data.AddEntry(null, "bob", " пробелы ", "Без группы");
            Entry trashed = data.AddEntry(null, "gone", "x", "Удалённая");
            data.TrashEntries(new[] { trashed.Id });

            string csv = VaultTransfer.ToCsv(data);
            Check(csv.StartsWith("name,url,username,password,note,group,totp\r\n"), "header: " + csv.Substring(0, Math.Min(60, csv.Length)));
            Check(!csv.Contains("Удалённая"), "the trash is not exported");

            ImportPlan plan = VaultTransfer.ReadCsv(csv);
            Check(plan.Error == null && plan.Entries.Count == 2 && plan.Skipped == 0, "the exported file is read back");

            VaultData copy = VaultData.CreateEmpty();
            VaultTransfer.Import(copy, plan, "Импорт");
            Entry mail = null;
            Entry bob = null;
            foreach (Entry entry in copy.Entries)
            {
                if (entry.Login == "alice") mail = entry;
                if (entry.Login == "bob") bob = entry;
            }
            Check(mail != null && mail.Password == "p,\"q\" ;" && mail.Description == "Почта\nвторая строка\nтретья", "password and description survive");
            Check(mail.Url == "https://mail.example.com" && mail.Totp == "JBSWY3DPEHPK3PXP", "website and key survive");
            Check(copy.GroupPath(mail.GroupId) == "Импорт / Работа / Серверы", "the group path survives: " + copy.GroupPath(mail.GroupId));
            Check(bob != null && bob.Password == " пробелы " && bob.Description == "Без группы", "spaces in a password survive");
        }

        // ---------- Язык интерфейса ----------

        private static void LocalisationBasics()
        {
            Func<int, string> entries = delegate(int n) { return L.Plural(n, "запись", "записи", "записей", "entry", "entries"); };
            var moment = new DateTime(2026, 3, 9, 7, 5, 0);

            Language before = L.Current;
            try
            {
                L.Current = Language.Russian;
                Check(L.T("да", "yes") == "да" && !L.IsEnglish, "russian text is chosen");
                Check(entries(1) == "1 запись" && entries(2) == "2 записи" && entries(5) == "5 записей", "russian plural forms");
                Check(entries(11) == "11 записей" && entries(21) == "21 запись" && entries(112) == "112 записей" && entries(0) == "0 записей",
                    "russian plural forms of larger numbers");
                Check(L.F("{0} из {1}", "{0} of {1}", 3, 8) == "3 из 8", "formatting in Russian");
                Check(L.FormatTime(moment) == "09.03.2026 07:05", "russian date: " + L.FormatTime(moment));
                Check(VaultData.CreateEmpty().ValidateGroupName(" ", null, null) == "Введите название группы.", "model messages in Russian");

                L.Current = Language.English;
                Check(L.T("да", "yes") == "yes" && L.IsEnglish, "english text is chosen");
                Check(entries(1) == "1 entry" && entries(2) == "2 entries" && entries(0) == "0 entries" && entries(21) == "21 entries",
                    "english plural forms");
                Check(L.F("{0} из {1}", "{0} of {1}", 3, 8) == "3 of 8", "formatting in English");
                Check(L.FormatTime(moment) == "2026-03-09 07:05", "english date: " + L.FormatTime(moment));
                Check(VaultData.CreateEmpty().ValidateGroupName(" ", null, null) == "Enter a group name.", "model messages in English");
                try
                {
                    VaultFormat.ParseHeader(new byte[100]);
                    Check(false, "a foreign file must be rejected");
                }
                catch (VaultException ex)
                {
                    Check(ex.Message.Length > 10 && !HasCyrillic(ex.Message), "file errors in English: " + ex.Message);
                }

                Check(L.FromSetting("ru") == Language.Russian && L.FromSetting("EN") == Language.English, "explicit language setting");
                Check(L.FromSetting("auto") == L.DetectSystemLanguage() && L.FromSetting(null) == L.DetectSystemLanguage(),
                    "any other value follows the system");
            }
            finally
            {
                L.Current = before;
            }
        }

        /// <summary>
        /// Просматривает исходники программы. Любая строка с кириллицей должна быть русским
        /// вариантом в L.T, L.F или L.Plural, а в английских вариантах кириллицы быть не должно.
        /// Так нельзя добавить текст и забыть его перевести.
        /// </summary>
        private static void LocalisationCoverage()
        {
            string folder = FindSources();
            if (folder == null)
            {
                Console.WriteLine("      note: the src folder was not found next to the tests, the check is skipped");
                return;
            }

            var problems = new List<string>();
            int translated = 0;
            foreach (string file in Directory.GetFiles(folder, "*.cs", SearchOption.AllDirectories))
            {
                translated += ScanSource(Path.GetFileName(file), File.ReadAllText(file, Encoding.UTF8), problems);
            }

            Check(translated > 200, "the scan sees the texts of the program: " + translated);
            Check(problems.Count == 0, problems.Count + " problem(s): " +
                string.Join(" | ", problems.GetRange(0, Math.Min(5, problems.Count)).ToArray()));

            // Сама проверка тоже проверяется: непереведённая строка и кириллица в английском варианте ловятся.
            var planted = new List<string>();
            ScanSource("sample", "var a = \"привет\"; var b = L.T(\"да\", \"нет\"); var c = L.F(\"x\" + \"ы\", \"y\", f(1, 2)); // \"мимо\"", planted);
            Check(planted.Count == 2, "the scanner catches planted mistakes: " + string.Join(" | ", planted.ToArray()));
        }

        private sealed class LocalisationCall
        {
            public string Name;
            public int Depth;
            public int Argument;
        }

        /// <summary>Возвращает число найденных русских текстов, у которых есть перевод.</summary>
        private static int ScanSource(string name, string text, List<string> problems)
        {
            var calls = new List<LocalisationCall>();
            int depth = 0;
            int line = 1;
            int translated = 0;
            int i = 0;
            while (i < text.Length)
            {
                char c = text[i];
                if (c == '\n')
                {
                    line++;
                    i++;
                }
                else if (c == '/' && i + 1 < text.Length && text[i + 1] == '/')
                {
                    while (i < text.Length && text[i] != '\n') i++;
                }
                else if (c == '/' && i + 1 < text.Length && text[i + 1] == '*')
                {
                    i += 2;
                    while (i + 1 < text.Length && !(text[i] == '*' && text[i + 1] == '/'))
                    {
                        if (text[i] == '\n') line++;
                        i++;
                    }
                    i += 2;
                }
                else if (c == '\'')
                {
                    // Символьная константа: 'x', '\n', '\''.
                    i++;
                    while (i < text.Length && text[i] != '\'')
                    {
                        if (text[i] == '\\') i++;
                        i++;
                    }
                    i++;
                }
                else if (c == '"' || (c == '@' && i + 1 < text.Length && text[i + 1] == '"'))
                {
                    bool verbatim = c == '@';
                    int start = verbatim ? i + 2 : i + 1;
                    int end = start;
                    while (end < text.Length)
                    {
                        if (verbatim && text[end] == '"' && end + 1 < text.Length && text[end + 1] == '"')
                        {
                            end += 2;
                            continue;
                        }
                        if (!verbatim && text[end] == '\\')
                        {
                            end += 2;
                            continue;
                        }
                        if (text[end] == '"') break;
                        if (text[end] == '\n') line++;
                        end++;
                    }
                    end = Math.Min(end, text.Length);

                    string literal = text.Substring(start, end - start);
                    if (HasCyrillic(literal))
                    {
                        LocalisationCall call = calls.Count > 0 ? calls[calls.Count - 1] : null;
                        // Русский текст — первый аргумент L.T, L.F и L.Native либо одна из трёх русских форм в L.Plural.
                        bool inPlace = call != null &&
                            (call.Name == "Plural" ? call.Argument >= 1 && call.Argument <= 3 : call.Argument == 0);
                        if (inPlace)
                        {
                            translated++;
                        }
                        else
                        {
                            problems.Add(name + ":" + line + (call == null ? " has no translation: " : " is in the wrong argument: ") + literal);
                        }
                    }
                    i = end + 1;
                }
                else if (c == '(' || c == '[' || c == '{')
                {
                    depth++;
                    string callName = c == '(' ? LocalisationCallName(text, i) : null;
                    if (callName != null)
                    {
                        var call = new LocalisationCall();
                        call.Name = callName;
                        call.Depth = depth;
                        calls.Add(call);
                    }
                    i++;
                }
                else if (c == ')' || c == ']' || c == '}')
                {
                    if (c == ')' && calls.Count > 0 && calls[calls.Count - 1].Depth == depth) calls.RemoveAt(calls.Count - 1);
                    depth--;
                    i++;
                }
                else
                {
                    if (c == ',' && calls.Count > 0 && calls[calls.Count - 1].Depth == depth) calls[calls.Count - 1].Argument++;
                    i++;
                }
            }
            return translated;
        }

        /// <summary>Если скобка в позиции open открывает вызов L.T, L.F, L.Plural или L.Native — имя метода, иначе null.</summary>
        private static string LocalisationCallName(string text, int open)
        {
            int end = open;
            while (end > 0 && char.IsWhiteSpace(text[end - 1])) end--;
            foreach (string name in new[] { "T", "F", "Plural", "Native" })
            {
                string token = "L." + name;
                int start = end - token.Length;
                if (start < 0 || string.CompareOrdinal(text, start, token, 0, token.Length) != 0) continue;
                if (start == 0) return name;
                char before = text[start - 1];
                if (!char.IsLetterOrDigit(before) && before != '_' && before != '.') return name;
            }
            return null;
        }

        private static bool HasCyrillic(string text)
        {
            foreach (char c in text)
            {
                if (c >= 0x0400 && c <= 0x04FF) return true;
            }
            return false;
        }

        private static string FindSources()
        {
            var candidates = new List<string>();
            candidates.Add(Path.Combine(Environment.CurrentDirectory, "src"));
            string folder = AppDomain.CurrentDomain.BaseDirectory;
            for (int i = 0; i < 4 && !string.IsNullOrEmpty(folder); i++)
            {
                candidates.Add(Path.Combine(folder, "src"));
                folder = Path.GetDirectoryName(folder.TrimEnd(Path.DirectorySeparatorChar));
            }
            foreach (string candidate in candidates)
            {
                if (File.Exists(Path.Combine(candidate, "L.cs"))) return candidate;
            }
            return null;
        }

        // ---------- Прочее ----------

        private static void GeneratorOptions()
        {
            // Только цифры.
            for (int i = 0; i < 100; i++)
            {
                string digits = PasswordGenerator.Generate(12, false, false, true, false, false);
                Check(digits.Length == 12 && System.Text.RegularExpressions.Regex.IsMatch(digits, "^[0-9]{12}$"), "digits only: " + digits);
            }

            // Без запрета похожих символов используется весь алфавит, с запретом — нет.
            var all = new HashSet<char>();
            var clear = new HashSet<char>();
            for (int i = 0; i < 400; i++)
            {
                foreach (char c in PasswordGenerator.Generate(40, true, true, true, false, false)) all.Add(c);
                foreach (char c in PasswordGenerator.Generate(40, true, true, true, false, true)) clear.Add(c);
            }
            Check(all.Count == 62, "letters and digits, nothing else: " + all.Count);
            foreach (char c in "O0Il1o")
            {
                Check(all.Contains(c), "the full alphabet includes " + c);
                Check(!clear.Contains(c), "look-alikes are left out: " + c);
            }
            Check(clear.Count == 56, "the alphabet without look-alikes: " + clear.Count);

            // Каждый выбранный класс представлен, невыбранных нет.
            for (int i = 0; i < 300; i++)
            {
                string password = PasswordGenerator.Generate(6, true, false, true, true, true);
                bool upper = false, lower = false, digit = false, symbol = false;
                foreach (char c in password)
                {
                    if (char.IsUpper(c)) upper = true;
                    else if (char.IsLower(c)) lower = true;
                    else if (char.IsDigit(c)) digit = true;
                    else symbol = true;
                }
                Check(upper && digit && symbol && !lower, "classes of " + password);
            }

            bool rejected = false;
            try
            {
                PasswordGenerator.Generate(10, false, false, false, false, true);
            }
            catch (ArgumentException)
            {
                rejected = true;
            }
            Check(rejected, "no character class at all is an error");

            rejected = false;
            try
            {
                PasswordGenerator.Generate(3, true, true, true, true, true);
            }
            catch (ArgumentOutOfRangeException)
            {
                rejected = true;
            }
            Check(rejected, "a password shorter than the number of classes is an error");
        }

        private static void GeneratorProperties()
        {
            const string allowed = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*-_=+?";
            var seen = new HashSet<string>();
            var counts = new Dictionary<char, int>();
            const int runs = 2000;

            for (int i = 0; i < runs; i++)
            {
                string password = PasswordGenerator.Generate(PasswordGenerator.DefaultLength);
                Check(password.Length == PasswordGenerator.DefaultLength, "length");
                Check(seen.Add(password), "passwords do not repeat");

                bool upper = false, lower = false, digit = false, symbol = false;
                foreach (char c in password)
                {
                    Check(allowed.IndexOf(c) >= 0, "unexpected character " + c);
                    if (char.IsUpper(c)) upper = true;
                    else if (char.IsLower(c)) lower = true;
                    else if (char.IsDigit(c)) digit = true;
                    else symbol = true;

                    int n;
                    counts.TryGetValue(c, out n);
                    counts[c] = n + 1;
                }
                Check(upper && lower && digit && symbol, "every character class is present: " + password);
            }

            Check(counts.Count == allowed.Length, "every character of the alphabet is used");
            Check("0O1lIo".IndexOfAny(new List<char>(counts.Keys).ToArray()) < 0, "look-alike characters are excluded");

            // Позиции равноправны: обязательные символы не должны оседать в начале.
            int firstIsUpper = 0;
            for (int i = 0; i < runs; i++)
            {
                if (char.IsUpper(PasswordGenerator.Generate(PasswordGenerator.DefaultLength)[0])) firstIsUpper++;
            }
            double share = firstIsUpper / (double)runs;
            Check(share > 0.25 && share < 0.50, "first character is not biased towards upper case: " + share);

            Check(PasswordGenerator.Generate(4).Length == 4 && PasswordGenerator.Generate(64).Length == 64, "other lengths");
            try
            {
                PasswordGenerator.Generate(3);
            }
            catch (ArgumentOutOfRangeException)
            {
                return;
            }
            throw new Exception("too short length must be rejected");
        }

        private static void LargeVault()
        {
            string path = NewVaultPath("large");
            const int count = 5000;
            Stopwatch watch;

            using (VaultSession session = VaultSession.Create(path, Password, FastIterations))
            {
                var groups = new List<Group>();
                for (int g = 0; g < 50; g++) groups.Add(session.Data.AddGroup("Группа " + g));
                for (int i = 0; i < count; i++)
                {
                    session.Data.AddEntry(groups[i % groups.Count].Id, "user" + i + "@example.com", PasswordGenerator.Generate(20), "Запись номер " + i + "\nс описанием на две строки");
                }
                watch = Stopwatch.StartNew();
                session.Save();
                watch.Stop();
            }
            long saveMs = watch.ElapsedMilliseconds;

            watch = Stopwatch.StartNew();
            using (VaultSession session = VaultSession.Open(path, Password))
            {
                watch.Stop();
                Check(session.Data.Entries.Count == count, "all entries are read back");
                Check(session.Data.Entries[count - 1].Login == "user" + (count - 1) + "@example.com", "last entry");

                Stopwatch query = Stopwatch.StartNew();
                int found = session.Data.Query(GroupFilter.All, "номер 4999").Count;
                query.Stop();
                Check(found == 1, "search in a large vault");
                Console.WriteLine("      save {0} ms, open {1} ms, search {2} ms, file {3} KB",
                    saveMs, watch.ElapsedMilliseconds, query.ElapsedMilliseconds, new FileInfo(path).Length / 1024);
            }
            Check(saveMs < 5000 && watch.ElapsedMilliseconds < 5000, "large vault is fast enough");
        }

        private static void Interop()
        {
            // 1. Файл, записанный независимой реализацией на Node.js (tests/interop.js write).
            string nodeFile = Path.Combine(workDir, "node.vault");
            if (File.Exists(nodeFile))
            {
                using (VaultSession session = VaultSession.Open(nodeFile, InteropPassword))
                {
                    VaultData data = session.Data;
                    Check(data.Groups.Count == 2 && data.Groups[0].Name == "Работа" && data.Groups[1].Name == "Проекты", "node file: groups");
                    Check(data.Groups[0].ParentId == null && data.Groups[1].ParentId == data.Groups[0].Id, "node file: nested group");
                    Check(data.Entries.Count == 1, "node file: entry count");
                    Entry entry = data.Entries[0];
                    Check(entry.GroupId == data.Groups[1].Id, "node file: group reference");
                    Check(data.GroupPath(entry.GroupId) == "Работа / Проекты", "node file: group path");
                    Check(entry.Login == "user@example.com", "node file: login");
                    Check(entry.Password == InteropSecret, "node file: password");
                    Check(entry.Description == "Строка 1\nСтрока 2", "node file: description");
                }
                Console.WriteLine("      node.vault written by Node.js opens here");
            }
            else
            {
                Console.WriteLine("      node.vault not found - skipped (run tests\\run-tests.cmd with Node.js installed)");
            }

            // 2. Файл для проверки в Node.js (tests/interop.js verify).
            string csFile = Path.Combine(workDir, "cs.vault");
            AtomicFile.TryDelete(csFile);
            AtomicFile.TryDelete(VaultSession.BackupPath(csFile));
            using (VaultSession session = VaultSession.Create(csFile, InteropPassword, 5000))
            {
                Group group = session.Data.AddGroup("Работа");
                Group nested = session.Data.AddGroup("Проекты", group.Id);
                session.Data.AddEntry(nested.Id, "user@example.com", InteropSecret, "Строка 1\r\nСтрока 2");
                session.Save();
            }
            using (VaultSession reopened = VaultSession.Open(csFile, InteropPassword))
            {
                Check(reopened.Data.Version == 2 && reopened.Data.Groups.Count == 2, "a nested vault survives encryption and reopening");
                Check(reopened.Data.GroupPath(reopened.Data.Entries[0].GroupId) == "Работа / Проекты", "group path after reopening");
            }

            // 3. Формат версии 2 (Argon2id, ключевой файл), записанный Node.js.
            string nodeFile2 = Path.Combine(workDir, "node2.vault");
            string nodeKey2 = Path.Combine(workDir, "node2.key");
            if (File.Exists(nodeFile2) && File.Exists(nodeKey2))
            {
                byte[] nodeKeyFile = VaultSession.ReadKeyFile(nodeKey2);
                using (VaultSession session = VaultSession.Open(nodeFile2, InteropPassword, nodeKeyFile))
                {
                    VaultData data = session.Data;
                    Check(session.Protection.IsArgon2 && session.UsesKeyFile, "node file 2: Argon2id with a key file");
                    Check(data.Version == 3 && data.Entries.Count == 2 && data.LiveCount == 1 && data.TrashCount == 1, "node file 2: entries and the trash");
                    Entry entry = data.Query(GroupFilter.All, null)[0];
                    Check(entry.Password == InteropSecret && entry.Url == "https://example.com/login" && entry.Totp == "JBSWY3DPEHPK3PXP", "node file 2: fields");
                    Check(entry.History != null && entry.History.Count == 1 && entry.History[0].Password == "old-one", "node file 2: password history");
                }
                ExpectVaultError(VaultError.KeyFileRequired, delegate { VaultSession.Open(nodeFile2, InteropPassword); });
                ExpectVaultError(VaultError.WrongPassword, delegate { VaultSession.Open(nodeFile2, InteropPassword, VaultFormat.NewKeyFile()); });
                Console.WriteLine("      node2.vault (Argon2id, key file) written by Node.js opens here");
            }
            else
            {
                Console.WriteLine("      node2.vault not found - the version 2 format is not cross-checked (needs Node.js with crypto.argon2Sync)");
            }

            // 4. Такой же файл для проверки в Node.js.
            string csFile2 = Path.Combine(workDir, "cs2.vault");
            string csKey2 = Path.Combine(workDir, "cs2.key");
            AtomicFile.TryDelete(csFile2);
            AtomicFile.TryDelete(VaultSession.BackupPath(csFile2));
            byte[] csKeyFile = VaultFormat.NewKeyFile();
            File.WriteAllBytes(csKey2, csKeyFile);
            using (VaultSession session = VaultSession.Create(csFile2, InteropPassword, csKeyFile))
            {
                var fields = new EntryFields();
                fields.Login = "user@example.com";
                fields.Password = "old-one";
                fields.Description = "Строка 1\nСтрока 2";
                fields.Url = "https://example.com/login";
                fields.Totp = "JBSWY3DPEHPK3PXP";
                Entry entry = session.Data.AddEntry(fields);
                fields.Password = InteropSecret;
                session.Data.UpdateEntry(entry.Id, fields);
                Entry gone = session.Data.AddEntry(null, "gone", "x", "deleted entry");
                session.Data.TrashEntries(new[] { gone.Id });
                session.Save();
            }
        }

        private static void KdfTiming()
        {
            byte[] salt = Cng.RandomBytes(VaultFormat.SaltSize);
            VaultFormat.DeriveKey("warm-up", salt, 1000);

            Stopwatch watch = Stopwatch.StartNew();
            VaultFormat.DeriveKey(Password, salt, VaultFormat.DefaultIterations);
            watch.Stop();
            Console.WriteLine("      PBKDF2-HMAC-SHA512, {0} iterations: {1} ms", VaultFormat.DefaultIterations, watch.ElapsedMilliseconds);
            Check(watch.ElapsedMilliseconds < 10000, "unlock time is acceptable");

            KdfParameters argon = KdfParameters.Argon2(salt, false);
            watch = Stopwatch.StartNew();
            VaultFormat.DeriveKey(Password, null, argon);
            watch.Stop();
            Console.WriteLine("      Argon2id, {0} MiB, {1} passes, {2} threads ({3}-bit process, {4} processors): {5} ms",
                argon.MemoryKiB / 1024, argon.Iterations, argon.Parallelism, IntPtr.Size * 8, Environment.ProcessorCount, watch.ElapsedMilliseconds);
            Check(watch.ElapsedMilliseconds < 20000, "unlock time with Argon2id is acceptable");
        }

        // ---------- Инфраструктура ----------

        private static void Run(string name, Action test)
        {
            try
            {
                test();
                passed++;
                Console.WriteLine("ok    " + name);
            }
            catch (Exception ex)
            {
                failed++;
                Console.WriteLine("FAIL  " + name);
                Console.WriteLine("      " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static void Check(bool condition, string what)
        {
            if (!condition) throw new Exception("check failed: " + what);
        }

        private static void Equal(string expectedHex, byte[] actual)
        {
            Equal(Hex(expectedHex), actual);
        }

        private static void Equal(byte[] expected, byte[] actual)
        {
            if (!SameBytes(expected, actual))
            {
                throw new Exception("expected " + ToHex(expected) + ", got " + ToHex(actual));
            }
        }

        private static void NotEqual(byte[] a, byte[] b)
        {
            if (SameBytes(a, b)) throw new Exception("values must differ");
        }

        private static void ExpectVaultError(VaultError expected, Action action)
        {
            try
            {
                action();
            }
            catch (VaultException ex)
            {
                if (ex.Error != expected) throw new Exception("expected " + expected + ", got " + ex.Error + ": " + ex.Message);
                if (string.IsNullOrWhiteSpace(ex.Message)) throw new Exception("error without a message");
                return;
            }
            throw new Exception("expected a vault error " + expected + ", but nothing was thrown");
        }

        private static void ExpectValidation(Action action)
        {
            try
            {
                action();
            }
            catch (ValidationException ex)
            {
                if (string.IsNullOrWhiteSpace(ex.Message)) throw new Exception("validation error without a message");
                return;
            }
            throw new Exception("expected a validation error, but nothing was thrown");
        }

        private static VaultData FromJsonText(string json)
        {
            return VaultData.FromJson(Encoding.UTF8.GetBytes(json));
        }

        private static string NewVaultPath(string name)
        {
            string path = Path.Combine(workDir, name + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".vault");
            return path;
        }

        private static byte[] Ascii(string text)
        {
            return Encoding.ASCII.GetBytes(text);
        }

        private static byte[] Hex(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }

        private static string ToHex(byte[] bytes)
        {
            if (bytes == null) return "(null)";
            var builder = new StringBuilder(bytes.Length * 2);
            foreach (byte b in bytes) builder.Append(b.ToString("x2"));
            return builder.ToString();
        }

        private static bool SameBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i]) return false;
            }
            return true;
        }

        private static byte[] Slice(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        private static void WriteInt32(byte[] target, int offset, int value)
        {
            target[offset] = (byte)value;
            target[offset + 1] = (byte)(value >> 8);
            target[offset + 2] = (byte)(value >> 16);
            target[offset + 3] = (byte)(value >> 24);
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            if (needle.Length == 0) return 0;
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j]) j++;
                if (j == needle.Length) return i;
            }
            return -1;
        }
    }
}
