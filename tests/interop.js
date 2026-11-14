'use strict';
// Независимая реализация формата хранилища KeyBox на Node.js — только встроенный
// модуль crypto. Нужна, чтобы убедиться: формат описан точно и файл можно открыть
// стандартными средствами, без самой программы.
//
//   node interop.js write  <файл>   записать хранилище, которое затем открывает KeyBox
//   node interop.js verify <файл>   открыть хранилище, записанное KeyBox, и сверить содержимое
//
// Пароль и данные заданы здесь и в tests/CoreTests.cs одинаково.

const crypto = require('crypto');
const fs = require('fs');

// «й» записана двумя символами (и + кратка), в C# — одним: пароль приводится к NFC.
const PASSWORD = '\u041f\u0430\u0440\u043e\u043b\u044c-\u0438\u0306-\ud83d\udd11';
const SECRET = 'p@ss "quoted" \\ \u0441\u043b\u043e\u0432\u043e \ud83d\udd11 <tag> / \t';
const GROUP = '\u0420\u0430\u0431\u043e\u0442\u0430';                                   // «Работа»
const DESCRIPTION = '\u0421\u0442\u0440\u043e\u043a\u0430 1\n\u0421\u0442\u0440\u043e\u043a\u0430 2'; // «Строка 1\nСтрока 2»

const HEADER_SIZE = 58;
const TAG_SIZE = 16;

function deriveKey(password, salt, iterations) {
  return crypto.pbkdf2Sync(Buffer.from(password.normalize('NFC'), 'utf8'), salt, iterations, 32, 'sha512');
}

function openVault(file, password) {
  const data = fs.readFileSync(file);
  if (data.length < HEADER_SIZE + TAG_SIZE) throw new Error('file is too short');
  if (data.subarray(0, 6).toString('latin1') !== 'KEYBOX') throw new Error('bad signature');
  if (data.readUInt16LE(6) !== 1) throw new Error('unsupported format version');
  if (data[8] !== 1 || data[9] !== 1) throw new Error('unsupported algorithms');

  const iterations = data.readUInt32LE(10);
  const salt = data.subarray(14, 46);
  const nonce = data.subarray(46, 58);
  const header = data.subarray(0, HEADER_SIZE);
  const ciphertext = data.subarray(HEADER_SIZE, data.length - TAG_SIZE);
  const tag = data.subarray(data.length - TAG_SIZE);

  const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(password, salt, iterations), nonce);
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  const json = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(json.toString('utf8'));
}

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

  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(password, salt, iterations), nonce);
  cipher.setAAD(header);
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(content), 'utf8')), cipher.final()]);
  fs.writeFileSync(file, Buffer.concat([header, ciphertext, cipher.getAuthTag()]));
}

function check(condition, what) {
  if (!condition) throw new Error('check failed: ' + what);
}

const [mode, file] = process.argv.slice(2);

if (mode === 'write') {
  writeVault(file, PASSWORD, {
    version: 1,
    groups: [{ id: 'g1', name: GROUP }],
    entries: [{
      id: 'e1',
      groupId: 'g1',
      login: 'user@example.com',
      password: SECRET,
      description: DESCRIPTION,
      created: '2026-01-02T03:04:05Z',
      modified: '2026-01-02T03:04:05Z',
    }],
  }, 5000);
  console.log('ok    node: wrote ' + file);
} else if (mode === 'verify') {
  const vault = openVault(file, PASSWORD);
  check(vault.version === 1, 'version');
  check(vault.groups.length === 1 && vault.groups[0].name === GROUP, 'group');
  check(vault.entries.length === 1, 'entry count');
  const entry = vault.entries[0];
  check(entry.groupId === vault.groups[0].id, 'group reference');
  check(entry.login === 'user@example.com', 'login');
  check(entry.password === SECRET, 'password');
  check(entry.description === DESCRIPTION, 'description');
  check(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(entry.created), 'timestamp format');

  let rejected = false;
  try {
    openVault(file, PASSWORD + 'x');
  } catch (e) {
    rejected = true;
  }
  check(rejected, 'wrong password must be rejected');
  console.log('ok    node: opened ' + file + ' written by KeyBox, contents match');
} else {
  console.error('usage: node interop.js write|verify <file>');
  process.exit(2);
}
