# Матрица проверок 0.5.0

Проверки запускаются в GitHub Actions на одноразовых Ubuntu 24.04 amd64.
Сценарии `smoke_*.py` меняют ОС и не предназначены для рабочего сервера.

| Область | Что проверяется |
|---|---|
| Чистая установка | Настоящий диалог `installer.main`, без VPN / Hysteria / AmneziaWG / оба VPN, службы и создание пользователей |
| Стартовые меню | Выход, неверный пункт и повтор ввода, отмена установки/обновления, проверка, локальная копия, переход к восстановлению |
| Ввод | Кириллица и Backspace в терминале, неверный UTF-8, домены, DNS, email, номера и занятость портов |
| Обновление | Закреплённая версия 0.4.0-beta.4 → 0.5.0, доустановка протоколов, сохранение владельца и пользователей |
| Сбой обновления | Ошибка до резервной копии, частичная установка VPN, ошибка активации, возврат старых ключей и настроек, готовность служб |
| Вход | Первый код владельца, пароль, настройка 2FA, одноразовые резервные коды, запрет повторного использования OTP |
| API | Авторизация, Host/Origin/CSRF, неверный JSON, отсутствие службы, запрет изменений при переносе |
| Telegram | Настоящие службы, проверка готовности, ключи, отзыв/замена/удаление, общая пауза, доступ к учёту |
| Общий Telegram-профиль | 32 клиента одновременно передают независимые данные через TCP-стенд; отключение одного не мешает остальным. Проверены 128 сессий с одним/разными IP, отказ нового входа без вытеснения старых и освобождение ёмкости |
| Местное время | Метки событий Telegram/Hysteria/AmneziaWG отображаются в часовом поясе браузера, включая переход через полночь. Календарь учёта и ранее сохранённые сроки не меняются |
| Hysteria | Настоящий QUIC-туннель, трафик, независимые пользователи, лимиты и сроки |
| AmneziaWG | Настоящий Go 3.1 TUN-туннель, трафик, отзыв, лимиты, перезапуск, изоляция клиентов и управления сервером |
| Онлайн | Свежесть статистики, границы handshake, пауза и запрет доступа, отсутствие ложного зелёного статуса |
| Браузерный ключ копий | X25519-ключ из JavaScript шифрует и расшифровывает через настоящий age |
| Архивы | Шифрование, неверный ключ, контрольные суммы, повреждённый манифест, ссылки/traversal, отсутствие данных VPN |
| Восстановление | Все 16 сочетаний набора протоколов копии/назначения, прежние ключи и ограничения, несовпадающие домены |
| Перенос | Финальная копия, остановка/ошибка/повтор/возобновление, standby, защита от запуска после перезагрузки |
| Мастер | Чистый VPS, выбор файлов, ожидание DNS/TLS, прерывание и продолжение без повторного импорта |
| Интерфейс | Навигация, выбранная карточка пользователя, неверные/устаревшие данные и мобильное отображение |

## Локальные проверки

На Linux с Flask, qrcode/Pillow, PyYAML, age, rclone и Node:

```sh
python3 -m unittest discover -s tests -v
node tests/test_awg_ui.js
node tests/test_backup_key.js
bash -n install.sh
shellcheck install.sh
```

Клиенты Android/Windows/iOS и фактическая сеть оператора проверяются отдельно.
Автотесты используют локальный тестовый CA для HTTPS; обычная установка
проверяет публичные сертификаты без отключения проверки TLS.
Настоящий перенос между двумя публичными IP требует двух VPS и переключения
DNS; проверка восстановления на одном хосте не подменяет этот сценарий.
Окончательные результаты релизного прогона публикуются вместе с релизом GitHub.
# AWG IPv4 routing — 2026-11-05

Branch: `codex/awg-ip-routing`.

- 119 Linux Python unit tests passed, including legacy profile migration,
  unchanged client configurations/keys, mode isolation, GeoIP validation,
  last-good retention, rollback, pending connection-reset retry, owner/CSRF
  protection, and portable database backup/restore.
- Six existing Node UI checks passed; AWG checks also cover the mode selector,
  default for new profiles, GeoIP status and unavailable-service controls.
- `tests/smoke_cascade.py` passed in temporary Linux network namespaces:
  real WireGuard cascade, complete 12,987-prefix seed loaded into nftables,
  separate full/split client source IPs, RU/foreign egress, scoped UDP NAT reset,
  missing GeoIP data, foreign tunnel outage without direct fallback, recovery,
  management traffic and explicit global cascade disable.
- A live HTTPS download from the configured GeoIP source passed validation and
  matched the bundled seed. The production exit service remained active and all
  test namespaces were cleaned up.

These checks did not install the branch on the production RU server. The new
network test uses veth to supply decrypted AWG-like packets; it does not replace
an acceptance test with a real AWG client after deployment. Existing client
config generation and the AWG transport implementation are unchanged. DNS and
domain routing are intentionally excluded.
