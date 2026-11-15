using System;
using System.Threading.Tasks;

namespace KeyBox.Crypto
{
    /// <summary>
    /// BLAKE2b (RFC 7693) без ключа, с результатом длиной от 1 до 64 байт.
    /// В программе нужна только как составная часть Argon2.
    /// </summary>
    internal static class Blake2b
    {
        private const int BlockSize = 128;

        private static readonly ulong[] IV =
        {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
        };

        private static readonly byte[][] Sigma =
        {
            new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            new byte[] { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
            new byte[] { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
            new byte[] { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
            new byte[] { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
            new byte[] { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
            new byte[] { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
            new byte[] { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
            new byte[] { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
            new byte[] { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
            new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
            new byte[] { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
        };

        public static byte[] Hash(byte[] data, int outputLength)
        {
            if (data == null) throw new ArgumentNullException("data");
            if (outputLength < 1 || outputLength > 64) throw new ArgumentOutOfRangeException("outputLength");

            var h = (ulong[])IV.Clone();
            h[0] ^= 0x01010000UL ^ (ulong)outputLength;

            var block = new ulong[16];
            var v = new ulong[16];
            int offset = 0;
            ulong counter = 0;

            // Все блоки, кроме последнего. Последний (возможно, неполный или пустой) идёт с признаком конца.
            while (data.Length - offset > BlockSize)
            {
                Load(data, offset, BlockSize, block);
                counter += BlockSize;
                Compress(h, block, v, counter, false);
                offset += BlockSize;
            }
            int rest = data.Length - offset;
            Load(data, offset, rest, block);
            counter += (ulong)rest;
            Compress(h, block, v, counter, true);

            var full = new byte[64];
            for (int i = 0; i < 8; i++)
            {
                ulong word = h[i];
                for (int b = 0; b < 8; b++)
                {
                    full[i * 8 + b] = (byte)(word >> (8 * b));
                }
            }
            var result = new byte[outputLength];
            Buffer.BlockCopy(full, 0, result, 0, outputLength);

            Array.Clear(full, 0, full.Length);
            Array.Clear(h, 0, h.Length);
            Array.Clear(block, 0, block.Length);
            Array.Clear(v, 0, v.Length);
            return result;
        }

        /// <summary>Читает до 128 байт как шестнадцать 64-разрядных слов (младший байт первым), дополняя нулями.</summary>
        private static void Load(byte[] data, int offset, int count, ulong[] block)
        {
            Array.Clear(block, 0, block.Length);
            for (int i = 0; i < count; i++)
            {
                block[i >> 3] |= (ulong)data[offset + i] << (8 * (i & 7));
            }
        }

        private static void Compress(ulong[] h, ulong[] m, ulong[] v, ulong counter, bool last)
        {
            unchecked
            {
                for (int i = 0; i < 8; i++)
                {
                    v[i] = h[i];
                    v[i + 8] = IV[i];
                }
                v[12] ^= counter;
                if (last) v[14] = ~v[14];

                for (int round = 0; round < 12; round++)
                {
                    byte[] s = Sigma[round];
                    Mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
                    Mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
                    Mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
                    Mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
                    Mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
                    Mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
                    Mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
                    Mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
                }

                for (int i = 0; i < 8; i++)
                {
                    h[i] ^= v[i] ^ v[i + 8];
                }
            }
        }

        private static void Mix(ulong[] v, int a, int b, int c, int d, ulong x, ulong y)
        {
            unchecked
            {
                v[a] = v[a] + v[b] + x;
                v[d] = Rotate(v[d] ^ v[a], 32);
                v[c] = v[c] + v[d];
                v[b] = Rotate(v[b] ^ v[c], 24);
                v[a] = v[a] + v[b] + y;
                v[d] = Rotate(v[d] ^ v[a], 16);
                v[c] = v[c] + v[d];
                v[b] = Rotate(v[b] ^ v[c], 63);
            }
        }

        private static ulong Rotate(ulong value, int bits)
        {
            return (value >> bits) | (value << (64 - bits));
        }
    }

    /// <summary>
    /// Argon2id версии 1.3 (RFC 9106) — функция получения ключа из пароля, которой нужна не только
    /// работа процессора, но и много памяти. Это сдерживает подбор на видеокартах: на каждую
    /// попытку там приходится выделять те же десятки мегабайт.
    ///
    /// В Windows такой функции нет, поэтому она реализована здесь. Правильность проверяется
    /// эталонными значениями из RFC 9106 и сверкой с независимой реализацией (tests\CoreTests.cs,
    /// tests\interop.js).
    /// </summary>
    internal static class Argon2id
    {
        private const int Version = 0x13;
        private const int TypeId = 2;
        private const int WordsInBlock = 128;
        private const int BlockBytes = 1024;
        private const int Slices = 4;

        public const int MinMemoryKiB = 8;

        /// <summary>Вторая из двух рекомендаций RFC 9106 (раздел 4): 3 прохода, 64 МиБ памяти, 4 потока.</summary>
        public const int DefaultPasses = 3;
        public const int DefaultMemoryKiB = 64 * 1024;
        public const int DefaultParallelism = 4;

        public static byte[] Hash(byte[] password, byte[] salt, int passes, int memoryKiB, int parallelism, int outputLength)
        {
            return Hash(password, salt, null, null, passes, memoryKiB, parallelism, outputLength);
        }

        /// <param name="password">Пароль (любые байты).</param>
        /// <param name="salt">Соль, не короче 8 байт.</param>
        /// <param name="secret">Необязательный секретный ключ (в программе не используется, нужен эталонным векторам).</param>
        /// <param name="associatedData">Необязательные дополнительные данные.</param>
        /// <param name="passes">Число проходов по памяти.</param>
        /// <param name="memoryKiB">Объём памяти в кибибайтах.</param>
        /// <param name="parallelism">Число независимых дорожек; они заполняются параллельно.</param>
        /// <param name="outputLength">Длина результата в байтах.</param>
        public static byte[] Hash(byte[] password, byte[] salt, byte[] secret, byte[] associatedData,
            int passes, int memoryKiB, int parallelism, int outputLength)
        {
            if (password == null) throw new ArgumentNullException("password");
            if (salt == null) throw new ArgumentNullException("salt");
            if (salt.Length < 8) throw new ArgumentException("The salt must be at least 8 bytes long.", "salt");
            if (passes < 1) throw new ArgumentOutOfRangeException("passes");
            if (parallelism < 1 || parallelism > 255) throw new ArgumentOutOfRangeException("parallelism");
            if (memoryKiB < MinMemoryKiB * parallelism) throw new ArgumentOutOfRangeException("memoryKiB");
            if (outputLength < 4) throw new ArgumentOutOfRangeException("outputLength");

            int lanes = parallelism;
            int blocks = memoryKiB - memoryKiB % (Slices * lanes);
            int laneLength = blocks / lanes;
            int segmentLength = laneLength / Slices;

            byte[] seed = InitialHash(password, salt, secret, associatedData, passes, memoryKiB, parallelism, outputLength);
            var memory = new ulong[(long)blocks * WordsInBlock];
            try
            {
                // Первые два блока каждой дорожки получаются прямо из пароля и параметров.
                var input = new byte[seed.Length + 8];
                Buffer.BlockCopy(seed, 0, input, 0, seed.Length);
                for (int lane = 0; lane < lanes; lane++)
                {
                    WriteInt32(input, seed.Length + 4, lane);
                    for (int index = 0; index < 2; index++)
                    {
                        WriteInt32(input, seed.Length, index);
                        byte[] bytes = LongHash(input, BlockBytes);
                        LoadBlock(bytes, memory, (lane * laneLength + index) * WordsInBlock);
                        Array.Clear(bytes, 0, bytes.Length);
                    }
                }
                Array.Clear(input, 0, input.Length);

                // Память заполняется по четвертям: внутри четверти дорожки не зависят друг от друга
                // и считаются параллельно, а между четвертями сверяются.
                for (int pass = 0; pass < passes; pass++)
                {
                    for (int slice = 0; slice < Slices; slice++)
                    {
                        int currentPass = pass;
                        int currentSlice = slice;
                        if (lanes == 1)
                        {
                            FillSegment(memory, currentPass, 0, currentSlice, lanes, laneLength, segmentLength, blocks, passes);
                        }
                        else
                        {
                            Parallel.For(0, lanes, delegate(int lane)
                            {
                                FillSegment(memory, currentPass, lane, currentSlice, lanes, laneLength, segmentLength, blocks, passes);
                            });
                        }
                    }
                }

                // Результат — из последних блоков всех дорожек.
                var final = new ulong[WordsInBlock];
                for (int lane = 0; lane < lanes; lane++)
                {
                    int last = (lane * laneLength + laneLength - 1) * WordsInBlock;
                    for (int i = 0; i < WordsInBlock; i++)
                    {
                        final[i] ^= memory[last + i];
                    }
                }
                var finalBytes = new byte[BlockBytes];
                for (int i = 0; i < WordsInBlock; i++)
                {
                    ulong word = final[i];
                    for (int b = 0; b < 8; b++)
                    {
                        finalBytes[i * 8 + b] = (byte)(word >> (8 * b));
                    }
                }
                byte[] result = LongHash(finalBytes, outputLength);
                Array.Clear(final, 0, final.Length);
                Array.Clear(finalBytes, 0, finalBytes.Length);
                return result;
            }
            finally
            {
                Array.Clear(memory, 0, memory.Length);
                Array.Clear(seed, 0, seed.Length);
            }
        }

        /// <summary>H0 из RFC 9106: все параметры и входные данные, свёрнутые в 64 байта.</summary>
        private static byte[] InitialHash(byte[] password, byte[] salt, byte[] secret, byte[] associatedData,
            int passes, int memoryKiB, int parallelism, int outputLength)
        {
            secret = secret ?? new byte[0];
            associatedData = associatedData ?? new byte[0];

            var buffer = new byte[24 + 16 + password.Length + salt.Length + secret.Length + associatedData.Length];
            int position = 0;
            position = WriteInt32(buffer, position, parallelism);
            position = WriteInt32(buffer, position, outputLength);
            position = WriteInt32(buffer, position, memoryKiB);
            position = WriteInt32(buffer, position, passes);
            position = WriteInt32(buffer, position, Version);
            position = WriteInt32(buffer, position, TypeId);
            position = WriteBytes(buffer, position, password);
            position = WriteBytes(buffer, position, salt);
            position = WriteBytes(buffer, position, secret);
            WriteBytes(buffer, position, associatedData);

            byte[] hash = Blake2b.Hash(buffer, 64);
            Array.Clear(buffer, 0, buffer.Length);
            return hash;
        }

        /// <summary>H' из RFC 9106: хеш произвольной длины, собранный из BLAKE2b.</summary>
        private static byte[] LongHash(byte[] input, int length)
        {
            var prefixed = new byte[4 + input.Length];
            WriteInt32(prefixed, 0, length);
            Buffer.BlockCopy(input, 0, prefixed, 4, input.Length);
            try
            {
                if (length <= 64) return Blake2b.Hash(prefixed, length);

                var output = new byte[length];
                byte[] v = Blake2b.Hash(prefixed, 64);
                Buffer.BlockCopy(v, 0, output, 0, 32);
                int position = 32;
                while (length - position > 64)
                {
                    byte[] next = Blake2b.Hash(v, 64);
                    Array.Clear(v, 0, v.Length);
                    v = next;
                    Buffer.BlockCopy(v, 0, output, position, 32);
                    position += 32;
                }
                byte[] tail = Blake2b.Hash(v, length - position);
                Buffer.BlockCopy(tail, 0, output, position, tail.Length);
                Array.Clear(v, 0, v.Length);
                Array.Clear(tail, 0, tail.Length);
                return output;
            }
            finally
            {
                Array.Clear(prefixed, 0, prefixed.Length);
            }
        }

        private static void FillSegment(ulong[] memory, int pass, int lane, int slice,
            int lanes, int laneLength, int segmentLength, int blocks, int passes)
        {
            // Argon2id: первая половина первого прохода не зависит от данных (защита от утечек
            // по времени), остальное зависит (защита от подбора со сниженной памятью).
            bool independent = pass == 0 && slice < Slices / 2;

            var r = new ulong[WordsInBlock];
            var saved = new ulong[WordsInBlock];
            ulong[] input = null;
            ulong[] addresses = null;
            ulong[] zero = null;
            if (independent)
            {
                input = new ulong[WordsInBlock];
                addresses = new ulong[WordsInBlock];
                zero = new ulong[WordsInBlock];
                input[0] = (ulong)pass;
                input[1] = (ulong)lane;
                input[2] = (ulong)slice;
                input[3] = (ulong)blocks;
                input[4] = (ulong)passes;
                input[5] = TypeId;
            }

            int start = 0;
            if (pass == 0 && slice == 0)
            {
                start = 2; // первые два блока дорожки уже готовы
                if (independent) NextAddresses(input, addresses, zero, r, saved);
            }

            int current = lane * laneLength + slice * segmentLength + start;
            int previous = current % laneLength == 0 ? current + laneLength - 1 : current - 1;

            for (int index = start; index < segmentLength; index++, current++, previous++)
            {
                if (current % laneLength == 1) previous = current - 1;

                ulong random;
                if (independent)
                {
                    if (index % WordsInBlock == 0) NextAddresses(input, addresses, zero, r, saved);
                    random = addresses[index % WordsInBlock];
                }
                else
                {
                    random = memory[previous * WordsInBlock];
                }

                int referenceLane = (int)((random >> 32) % (ulong)lanes);
                if (pass == 0 && slice == 0) referenceLane = lane;
                int referenceIndex = ReferenceIndex(pass, slice, index, (uint)random, referenceLane == lane, laneLength, segmentLength);
                int reference = referenceLane * laneLength + referenceIndex;

                FillBlock(memory, previous * WordsInBlock, memory, reference * WordsInBlock, memory, current * WordsInBlock, pass != 0, r, saved);
            }
        }

        /// <summary>Номер блока в дорожке, на который ссылается новый блок (функция «index_alpha» эталонной реализации).</summary>
        private static int ReferenceIndex(int pass, int slice, int index, uint random, bool sameLane, int laneLength, int segmentLength)
        {
            int area;
            if (pass == 0)
            {
                if (slice == 0) area = index - 1;
                else if (sameLane) area = slice * segmentLength + index - 1;
                else area = slice * segmentLength + (index == 0 ? -1 : 0);
            }
            else
            {
                if (sameLane) area = laneLength - segmentLength + index - 1;
                else area = laneLength - segmentLength + (index == 0 ? -1 : 0);
            }

            unchecked
            {
                ulong relative = random;
                relative = (relative * relative) >> 32;
                relative = (ulong)area - 1 - (((ulong)area * relative) >> 32);

                int startPosition = 0;
                if (pass != 0 && slice != Slices - 1) startPosition = (slice + 1) * segmentLength;
                return (int)(((ulong)startPosition + relative) % (ulong)laneLength);
            }
        }

        /// <summary>Очередной блок псевдослучайных адресов для части, не зависящей от данных.</summary>
        private static void NextAddresses(ulong[] input, ulong[] addresses, ulong[] zero, ulong[] r, ulong[] saved)
        {
            input[6]++;
            FillBlock(zero, 0, input, 0, addresses, 0, false, r, saved);
            FillBlock(zero, 0, addresses, 0, addresses, 0, false, r, saved);
        }

        /// <summary>
        /// Функция сжатия G: новый блок из предыдущего и опорного. При повторных проходах
        /// результат дополнительно складывается с прежним содержимым блока.
        /// </summary>
        private static void FillBlock(ulong[] previous, int previousAt, ulong[] reference, int referenceAt,
            ulong[] next, int nextAt, bool withXor, ulong[] r, ulong[] saved)
        {
            for (int i = 0; i < WordsInBlock; i++)
            {
                ulong word = reference[referenceAt + i] ^ previous[previousAt + i];
                r[i] = word;
                saved[i] = withXor ? word ^ next[nextAt + i] : word;
            }

            // Перестановка сначала по восьми «столбцам» блока (по 16 слов подряд), затем по восьми «строкам».
            for (int column = 0; column < WordsInBlock; column += 16)
            {
                Round(r, column, 2);
            }
            for (int row = 0; row < 16; row += 2)
            {
                Round(r, row, 16);
            }

            for (int i = 0; i < WordsInBlock; i++)
            {
                next[nextAt + i] = saved[i] ^ r[i];
            }
        }

        /// <summary>
        /// Раунд BLAKE2b без сообщения над шестнадцатью словами блока: восемь пар слов, пара j
        /// начинается со слова start + j * stride. Сложение заменено на «сложение с умножением»
        /// (x + y + 2·lo(x)·lo(y)), как того требует Argon2.
        /// </summary>
        private static void Round(ulong[] v, int start, int stride)
        {
            unchecked
            {
                int i0 = start;
                int i1 = i0 + stride;
                int i2 = i1 + stride;
                int i3 = i2 + stride;
                int i4 = i3 + stride;
                int i5 = i4 + stride;
                int i6 = i5 + stride;
                int i7 = i6 + stride;

                ulong v0 = v[i0], v1 = v[i0 + 1], v2 = v[i1], v3 = v[i1 + 1];
                ulong v4 = v[i2], v5 = v[i2 + 1], v6 = v[i3], v7 = v[i3 + 1];
                ulong v8 = v[i4], v9 = v[i4 + 1], v10 = v[i5], v11 = v[i5 + 1];
                ulong v12 = v[i6], v13 = v[i6 + 1], v14 = v[i7], v15 = v[i7 + 1];

                // Столбцы: (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15).
                v0 = v0 + v4 + 2 * (v0 & 0xFFFFFFFFUL) * (v4 & 0xFFFFFFFFUL); v12 ^= v0; v12 = (v12 >> 32) | (v12 << 32);
                v8 = v8 + v12 + 2 * (v8 & 0xFFFFFFFFUL) * (v12 & 0xFFFFFFFFUL); v4 ^= v8; v4 = (v4 >> 24) | (v4 << 40);
                v0 = v0 + v4 + 2 * (v0 & 0xFFFFFFFFUL) * (v4 & 0xFFFFFFFFUL); v12 ^= v0; v12 = (v12 >> 16) | (v12 << 48);
                v8 = v8 + v12 + 2 * (v8 & 0xFFFFFFFFUL) * (v12 & 0xFFFFFFFFUL); v4 ^= v8; v4 = (v4 >> 63) | (v4 << 1);

                v1 = v1 + v5 + 2 * (v1 & 0xFFFFFFFFUL) * (v5 & 0xFFFFFFFFUL); v13 ^= v1; v13 = (v13 >> 32) | (v13 << 32);
                v9 = v9 + v13 + 2 * (v9 & 0xFFFFFFFFUL) * (v13 & 0xFFFFFFFFUL); v5 ^= v9; v5 = (v5 >> 24) | (v5 << 40);
                v1 = v1 + v5 + 2 * (v1 & 0xFFFFFFFFUL) * (v5 & 0xFFFFFFFFUL); v13 ^= v1; v13 = (v13 >> 16) | (v13 << 48);
                v9 = v9 + v13 + 2 * (v9 & 0xFFFFFFFFUL) * (v13 & 0xFFFFFFFFUL); v5 ^= v9; v5 = (v5 >> 63) | (v5 << 1);

                v2 = v2 + v6 + 2 * (v2 & 0xFFFFFFFFUL) * (v6 & 0xFFFFFFFFUL); v14 ^= v2; v14 = (v14 >> 32) | (v14 << 32);
                v10 = v10 + v14 + 2 * (v10 & 0xFFFFFFFFUL) * (v14 & 0xFFFFFFFFUL); v6 ^= v10; v6 = (v6 >> 24) | (v6 << 40);
                v2 = v2 + v6 + 2 * (v2 & 0xFFFFFFFFUL) * (v6 & 0xFFFFFFFFUL); v14 ^= v2; v14 = (v14 >> 16) | (v14 << 48);
                v10 = v10 + v14 + 2 * (v10 & 0xFFFFFFFFUL) * (v14 & 0xFFFFFFFFUL); v6 ^= v10; v6 = (v6 >> 63) | (v6 << 1);

                v3 = v3 + v7 + 2 * (v3 & 0xFFFFFFFFUL) * (v7 & 0xFFFFFFFFUL); v15 ^= v3; v15 = (v15 >> 32) | (v15 << 32);
                v11 = v11 + v15 + 2 * (v11 & 0xFFFFFFFFUL) * (v15 & 0xFFFFFFFFUL); v7 ^= v11; v7 = (v7 >> 24) | (v7 << 40);
                v3 = v3 + v7 + 2 * (v3 & 0xFFFFFFFFUL) * (v7 & 0xFFFFFFFFUL); v15 ^= v3; v15 = (v15 >> 16) | (v15 << 48);
                v11 = v11 + v15 + 2 * (v11 & 0xFFFFFFFFUL) * (v15 & 0xFFFFFFFFUL); v7 ^= v11; v7 = (v7 >> 63) | (v7 << 1);

                // Диагонали: (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14).
                v0 = v0 + v5 + 2 * (v0 & 0xFFFFFFFFUL) * (v5 & 0xFFFFFFFFUL); v15 ^= v0; v15 = (v15 >> 32) | (v15 << 32);
                v10 = v10 + v15 + 2 * (v10 & 0xFFFFFFFFUL) * (v15 & 0xFFFFFFFFUL); v5 ^= v10; v5 = (v5 >> 24) | (v5 << 40);
                v0 = v0 + v5 + 2 * (v0 & 0xFFFFFFFFUL) * (v5 & 0xFFFFFFFFUL); v15 ^= v0; v15 = (v15 >> 16) | (v15 << 48);
                v10 = v10 + v15 + 2 * (v10 & 0xFFFFFFFFUL) * (v15 & 0xFFFFFFFFUL); v5 ^= v10; v5 = (v5 >> 63) | (v5 << 1);

                v1 = v1 + v6 + 2 * (v1 & 0xFFFFFFFFUL) * (v6 & 0xFFFFFFFFUL); v12 ^= v1; v12 = (v12 >> 32) | (v12 << 32);
                v11 = v11 + v12 + 2 * (v11 & 0xFFFFFFFFUL) * (v12 & 0xFFFFFFFFUL); v6 ^= v11; v6 = (v6 >> 24) | (v6 << 40);
                v1 = v1 + v6 + 2 * (v1 & 0xFFFFFFFFUL) * (v6 & 0xFFFFFFFFUL); v12 ^= v1; v12 = (v12 >> 16) | (v12 << 48);
                v11 = v11 + v12 + 2 * (v11 & 0xFFFFFFFFUL) * (v12 & 0xFFFFFFFFUL); v6 ^= v11; v6 = (v6 >> 63) | (v6 << 1);

                v2 = v2 + v7 + 2 * (v2 & 0xFFFFFFFFUL) * (v7 & 0xFFFFFFFFUL); v13 ^= v2; v13 = (v13 >> 32) | (v13 << 32);
                v8 = v8 + v13 + 2 * (v8 & 0xFFFFFFFFUL) * (v13 & 0xFFFFFFFFUL); v7 ^= v8; v7 = (v7 >> 24) | (v7 << 40);
                v2 = v2 + v7 + 2 * (v2 & 0xFFFFFFFFUL) * (v7 & 0xFFFFFFFFUL); v13 ^= v2; v13 = (v13 >> 16) | (v13 << 48);
                v8 = v8 + v13 + 2 * (v8 & 0xFFFFFFFFUL) * (v13 & 0xFFFFFFFFUL); v7 ^= v8; v7 = (v7 >> 63) | (v7 << 1);

                v3 = v3 + v4 + 2 * (v3 & 0xFFFFFFFFUL) * (v4 & 0xFFFFFFFFUL); v14 ^= v3; v14 = (v14 >> 32) | (v14 << 32);
                v9 = v9 + v14 + 2 * (v9 & 0xFFFFFFFFUL) * (v14 & 0xFFFFFFFFUL); v4 ^= v9; v4 = (v4 >> 24) | (v4 << 40);
                v3 = v3 + v4 + 2 * (v3 & 0xFFFFFFFFUL) * (v4 & 0xFFFFFFFFUL); v14 ^= v3; v14 = (v14 >> 16) | (v14 << 48);
                v9 = v9 + v14 + 2 * (v9 & 0xFFFFFFFFUL) * (v14 & 0xFFFFFFFFUL); v4 ^= v9; v4 = (v4 >> 63) | (v4 << 1);

                v[i0] = v0; v[i0 + 1] = v1; v[i1] = v2; v[i1 + 1] = v3;
                v[i2] = v4; v[i2 + 1] = v5; v[i3] = v6; v[i3 + 1] = v7;
                v[i4] = v8; v[i4 + 1] = v9; v[i5] = v10; v[i5 + 1] = v11;
                v[i6] = v12; v[i6 + 1] = v13; v[i7] = v14; v[i7 + 1] = v15;
            }
        }

        private static void LoadBlock(byte[] bytes, ulong[] memory, int at)
        {
            for (int i = 0; i < WordsInBlock; i++)
            {
                ulong word = 0;
                for (int b = 7; b >= 0; b--)
                {
                    word = (word << 8) | bytes[i * 8 + b];
                }
                memory[at + i] = word;
            }
        }

        private static int WriteInt32(byte[] buffer, int position, int value)
        {
            buffer[position] = (byte)value;
            buffer[position + 1] = (byte)(value >> 8);
            buffer[position + 2] = (byte)(value >> 16);
            buffer[position + 3] = (byte)(value >> 24);
            return position + 4;
        }

        private static int WriteBytes(byte[] buffer, int position, byte[] value)
        {
            position = WriteInt32(buffer, position, value.Length);
            Buffer.BlockCopy(value, 0, buffer, position, value.Length);
            return position + value.Length;
        }
    }
}
