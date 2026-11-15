'use strict';
// Независимая реализация формата хранилища KeyBox на Node.js — только встроенный
// модуль crypto. Нужна, чтобы убедиться: формат описан точно и файл можно открыть
// стандартными средствами, без самой программы.
//
//   node interop.js write  <файл>   записать хранилище, которое затем открывает KeyBox
//   node interop.js verify <файл>   открыть хранилище, записанное KeyBox, и сверить содержимое
//
// Рядом с указанным файлом (формат версии 1, PBKDF2) так же пишется и проверяется второй —
// в формате версии 2: Argon2id и ключевой файл. Для него нужен Node.js, в котором есть
// crypto.argon2Sync; в более старом эта часть пропускается.
//
// Пароль и данные заданы здесь и в tests/CoreTests.cs одинаково.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const HAS_ARGON2 = typeof crypto.argon2Sync === 'function';

// «й» записана двумя символами (и + кратка), в C# — одним: пароль приводится к NFC.
const PASSWORD = '\u041f\u0430\u0440\u043e\u043b\u044c-\u0438\u0306-\ud83d\udd11';
const SECRET = 'p@ss "quoted" \\ \u0441\u043b\u043e\u0432\u043e \ud83d\udd11 <tag> / \t';
const GROUP = '\u0420\u0430\u0431\u043e\u0442\u0430';                                   // «Работа»
const DESCRIPTION = '\u0421\u0442\u0440\u043e\u043a\u0430 1\n\u0421\u0442\u0440\u043e\u043a\u0430 2'; // «Строка 1\nСтрока 2»

const SUBGROUP = 'Проекты';   // вложена в группу «Работа»

const HEADER_SIZE = 58;      // формат версии 1
const HEADER_SIZE_V2 = 68;   // формат версии 2
const TAG_SIZE = 16;

// Секрет для функции получения ключа: пароль в UTF-8 (в форме Юникода NFC).
// С ключевым файлом — HMAC-SHA512(ключ = SHA-512(файл), данные = пароль).
function secretOf(password, keyFile) {
  const bytes = Buffer.from(password.normalize('NFC'), 'utf8');
  if (!keyFile) return bytes;
  const fileHash = crypto.createHash('sha512').update(keyFile).digest();
  return crypto.createHmac('sha512', fileHash).update(bytes).digest();
}

function deriveKey(password, keyFile, kdf) {
  const secret = secretOf(password, keyFile);
  if (kdf.id === 1) {
    return crypto.pbkdf2Sync(secret, kdf.salt, kdf.iterations, 32, 'sha512');
  }
  return crypto.argon2Sync('argon2id', {
    message: secret,
    nonce: kdf.salt,
    passes: kdf.iterations,
    memory: kdf.memory,
    parallelism: kdf.parallelism,
    tagLength: 32,
  });
}

function parseHeader(data) {
  if (data.length < HEADER_SIZE + TAG_SIZE) throw new Error('file is too short');
  if (data.subarray(0, 6).toString('latin1') !== 'KEYBOX') throw new Error('bad signature');
  if (data[9] !== 1) throw new Error('unsupported cipher');

  const version = data.readUInt16LE(6);
  if (version === 1) {
    if (data[8] !== 1) throw new Error('unsupported key derivation');
    return {
      size: HEADER_SIZE,
      keyFile: false,
      kdf: { id: 1, iterations: data.readUInt32LE(10), salt: data.subarray(14, 46) },
      nonce: data.subarray(46, 58),
    };
  }
  if (version === 2) {
    if (data[8] !== 1 && data[8] !== 2) throw new Error('unsupported key derivation');
    if ((data[10] & 0xFE) !== 0 || data[11] !== 0) throw new Error('unknown flags');
    return {
      size: HEADER_SIZE_V2,
      keyFile: (data[10] & 1) !== 0,
      kdf: {
        id: data[8],
        iterations: data.readUInt32LE(12),
        memory: data.readUInt32LE(16),
        parallelism: data.readUInt32LE(20),
        salt: data.subarray(24, 56),
      },
      nonce: data.subarray(56, 68),
    };
  }
  throw new Error('unsupported format version');
}

function openVault(file, password, keyFile) {
  const data = fs.readFileSync(file);
  const header = parseHeader(data);
  if (header.keyFile && !keyFile) throw new Error('a key file is required');

  const key = deriveKey(password, header.keyFile ? keyFile : null, header.kdf);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, header.nonce);
  decipher.setAAD(data.subarray(0, header.size));
  decipher.setAuthTag(data.subarray(data.length - TAG_SIZE));
  const json = Buffer.concat([decipher.update(data.subarray(header.size, data.length - TAG_SIZE)), decipher.final()]);
  return JSON.parse(json.toString('utf8'));
}

function seal(file, header, key, nonce, content) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(content), 'utf8')), cipher.final()]);
  fs.writeFileSync(file, Buffer.concat([header, ciphertext, cipher.getAuthTag()]));
}

// Формат версии 1: PBKDF2-HMAC-SHA512.
function writeVault(file, password, content, iterations) {
  const salt = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);

  const header = Buffer.alloc(HEADER_SIZE);
  header.write('KEYBOX', 0, 'latin1');
  header.writeUInt16LE(1, 6);
  header[8] = 1;
  header[9] = 1;
  header.writeUInt32LE(iterations, 10);
  salt.copy(header, 14);
  nonce.copy(header, 46);

  seal(file, header, deriveKey(password, null, { id: 1, iterations, salt }), nonce, content);
}

// Формат версии 2: Argon2id (3 прохода, 64 МиБ, 4 дорожки) и, если задан, ключевой файл.
function writeVaultV2(file, password, keyFile, content) {
  const salt = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const kdf = { id: 2, iterations: 3, memory: 64 * 1024, parallelism: 4, salt };

  const header = Buffer.alloc(HEADER_SIZE_V2);
  header.write('KEYBOX', 0, 'latin1');
  header.writeUInt16LE(2, 6);
  header[8] = 2;
  header[9] = 1;
  header[10] = keyFile ? 1 : 0;
  header.writeUInt32LE(kdf.iterations, 12);
  header.writeUInt32LE(kdf.memory, 16);
  header.writeUInt32LE(kdf.parallelism, 20);
  salt.copy(header, 24);
  nonce.copy(header, 56);

  seal(file, header, deriveKey(password, keyFile, kdf), nonce, content);
}

function rejects(action) {
  try {
    action();
  } catch (e) {
    return true;
  }
  return false;
}

function check(condition, what) {
  if (!condition) throw new Error('check failed: ' + what);
}

const [mode, file] = process.argv.slice(2);

if (mode === 'write') {
  writeVault(file, PASSWORD, {
    version: 2,
    groups: [{ id: 'g1', name: GROUP }, { id: 'g2', name: SUBGROUP, parentId: 'g1' }],
    entries: [{
      id: 'e1',
      groupId: 'g2',
      login: 'user@example.com',
      password: SECRET,
      description: DESCRIPTION,
      created: '2026-01-02T03:04:05Z',
      modified: '2026-01-02T03:04:05Z',
    }],
  }, 5000);
  console.log('ok    node: wrote ' + file);

  // Второй файл: формат версии 2 с Argon2id и ключевым файлом, данные — с полями версии 3.
  const second = path.join(path.dirname(file), 'node2.vault');
  const secondKey = path.join(path.dirname(file), 'node2.key');
  for (const stale of [second, secondKey]) {
    if (fs.existsSync(stale)) fs.unlinkSync(stale);
  }
  if (HAS_ARGON2) {
    const keyFile = crypto.randomBytes(64);
    fs.writeFileSync(secondKey, keyFile);
    writeVaultV2(second, PASSWORD, keyFile, {
      version: 3,
      groups: [{ id: 'g1', name: GROUP }],
      entries: [{
        id: 'e1',
        groupId: 'g1',
        login: 'user@example.com',
        password: SECRET,
        description: DESCRIPTION,
        created: '2026-01-02T03:04:05Z',
        modified: '2026-01-02T03:04:05Z',
        url: 'https://example.com/login',
        totp: 'JBSWY3DPEHPK3PXP',
        history: [{ password: 'old-one', replaced: '2026-01-02T03:04:05Z' }],
      }, {
        id: 'e2',
        groupId: null,
        login: 'gone',
        password: 'x',
        description: 'deleted entry',
        created: '2026-01-02T03:04:05Z',
        modified: '2026-01-02T03:04:05Z',
        deleted: '2026-01-03T00:00:00Z',
      }],
    });
    console.log('ok    node: wrote ' + second + ' (Argon2id, key file)');
  } else {
    console.log('note: this Node.js has no crypto.argon2Sync, the version 2 format is not cross-checked');
  }
} else if (mode === 'verify') {
  const vault = openVault(file, PASSWORD);
  check(vault.version === 2, 'version 2: the vault uses nested groups');
  check(vault.groups.length === 2, 'group count');
  const parent = vault.groups.find((g) => g.name === GROUP);
  const child = vault.groups.find((g) => g.name === SUBGROUP);
  check(parent && !('parentId' in parent), 'top-level group has no parentId');
  check(child && child.parentId === parent.id, 'nested group points to its parent');
  check(vault.entries.length === 1, 'entry count');
  const entry = vault.entries[0];
  check(entry.groupId === child.id, 'group reference');
  check(entry.login === 'user@example.com', 'login');
  check(entry.password === SECRET, 'password');
  check(entry.description === DESCRIPTION, 'description');
  check(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(entry.created), 'timestamp format');

  check(rejects(() => openVault(file, PASSWORD + 'x')), 'wrong password must be rejected');
  console.log('ok    node: opened ' + file + ' written by KeyBox, contents match');

  // Второй файл: Argon2id и ключевой файл.
  const second = path.join(path.dirname(file), 'cs2.vault');
  const secondKey = path.join(path.dirname(file), 'cs2.key');
  if (HAS_ARGON2 && fs.existsSync(second)) {
    const keyFile = fs.readFileSync(secondKey);
    const raw = fs.readFileSync(second);
    check(raw.readUInt16LE(6) === 2 && raw[8] === 2 && raw[10] === 1, 'format version 2, Argon2id, key file flag');

    const vault2 = openVault(second, PASSWORD, keyFile);
    check(vault2.version === 3 && vault2.entries.length === 2, 'structure version 3, two entries');
    const live = vault2.entries.find((e) => !e.deleted);
    const trashed = vault2.entries.find((e) => e.deleted);
    check(live && live.password === SECRET && live.url === 'https://example.com/login', 'password and website');
    check(live.totp === 'JBSWY3DPEHPK3PXP', 'one-time code key');
    check(live.history && live.history.length === 1 && live.history[0].password === 'old-one', 'password history');
    check(trashed && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(trashed.deleted), 'an entry in the trash');

    check(rejects(() => openVault(second, PASSWORD + 'x', keyFile)), 'wrong password must be rejected');
    check(rejects(() => openVault(second, PASSWORD, crypto.randomBytes(64))), 'wrong key file must be rejected');
    check(rejects(() => openVault(second, PASSWORD, null)), 'a missing key file must be rejected');
    console.log('ok    node: opened ' + second + ' (Argon2id, key file) written by KeyBox, contents match');
  } else if (!HAS_ARGON2) {
    console.log('note: this Node.js has no crypto.argon2Sync, the version 2 format is not cross-checked');
  }
} else {
  console.error('usage: node interop.js write|verify <file>');
  process.exit(2);
}
