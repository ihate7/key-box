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

            workDir = args.Length > 0
                ? Path.GetFullPath(args[0])
                : Path.Combine(Path.GetTempPath(), "keybox-tests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(workDir);

            Run("pbkdf2-sha512: known answers", Pbkdf2KnownAnswers);
            Run("pbkdf2-sha512: matches .NET implementation", Pbkdf2MatchesManaged);
            Run("aes-256-gcm: NIST known answers", AesGcmKnownAnswers);
            Run("aes-256-gcm: round trip, all sizes", AesGcmRoundTrip);
            Run("aes-256-gcm: detects any modification", AesGcmDetectsTampering);
            Run("format: layout and round trip", FormatRoundTrip);
            Run("format: every flipped byte is rejected", FormatRejectsEveryFlippedByte);
            Run("format: truncated and foreign files are rejected", FormatRejectsTruncated);
            Run("format: header limits are enforced before the KDF runs", FormatHeaderLimits);
            Run("format: fresh nonce on every save", FormatFreshNonce);
            Run("password: unicode and NFC normalisation", PasswordNormalisation);
            Run("session: create, save, reopen", SessionCreateSaveOpen);
            Run("session: wrong password", SessionWrongPassword);
            Run("session: backup keeps the previous version", SessionBackup);
            Run("session: the same on file systems without atomic replace", SessionBackupSimpleReplace);
            Run("session: change master password", SessionChangePassword);
            Run("session: no plaintext or leftovers on disk", SessionNoPlaintextOnDisk);
            Run("session: disposed session cannot save", SessionDisposed);
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
            Run("json: unicode and special characters", JsonSpecialCharacters);
            Run("json: damaged and foreign data", JsonNormalisation);
            Run("generator: alphabet, classes, uniqueness", GeneratorProperties);
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
            newer[6] = 2;
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

                Check(session.Iterations == VaultFormat.DefaultIterations, "old vaults are upgraded to the current iteration count");
                Check(!SameBytes(Slice(before, 14, 32), Slice(after, 14, 32)), "salt changes with the password");
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

            ExpectVaultError(VaultError.UnsupportedVersion, delegate { FromJsonText("{\"version\":3,\"groups\":[],\"entries\":[]}"); });
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

        // ---------- Прочее ----------

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
