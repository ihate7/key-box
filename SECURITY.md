# Безопасность

KeyBox хранит пароли, поэтому сообщения об уязвимостях здесь особенно важны.

## Как сообщить об уязвимости

Не описывайте уязвимость в открытом обсуждении (issue): до выхода исправления подробности
увидят все.

Напишите приватно: на странице репозитория откройте вкладку **Security** и нажмите
**Report a vulnerability** — или сразу перейдите к
[форме сообщения](https://github.com/ihate7/key-box/security/advisories/new).
Такое сообщение видит только автор проекта.

В сообщении укажите:

- версию программы (меню «⋯» → «О программе») и версию Windows;
- что именно удаётся сделать и при каких условиях;
- шаги, по которым это можно повторить.

Ответ придёт в том же обсуждении. После исправления выйдет новая версия, и в её описании
будет сказано, что исправлено.

## Что считается уязвимостью

- Возможность прочитать или изменить содержимое хранилища без мастер-пароля.
- Ошибки в шифровании, формате файла или генераторе паролей, которые ослабляют защиту.
- Случаи, когда пароли или мастер-пароль попадают на диск в открытом виде либо остаются
  в буфере обмена дольше, чем обещано.

## Что уязвимостью не считается

Ограничения, которые прямо названы в разделе «Безопасность» файла [README](README.md):
вредоносные программы на том же компьютере, слабый мастер-пароль, расшифрованные данные
в памяти открытой программы.

## Поддерживаемые версии

Исправления выходят только для последней версии программы.

## In English

KeyBox stores passwords, so vulnerability reports matter a lot here. Please do not describe
a vulnerability in a public issue. Report it privately instead: open the **Security** tab of
the repository and press **Report a vulnerability**, or go straight to the
[report form](https://github.com/ihate7/key-box/security/advisories/new). Include the program
version (menu “⋯” → “About”), the Windows version, what can be done and under which conditions,
and the steps to reproduce it. Fixes are released for the latest version only. The limits named
in the “Security” section of the [README](README.en.md) — malware on the same computer, a weak
master password, decrypted data in the memory of the running program — are not vulnerabilities.
