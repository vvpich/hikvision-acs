# Hikvision Access Control для Home Assistant

Локальная интеграция для терминалов контроля доступа Hikvision (проверено на
DS-K1T342MFWX и совместимых моделях линейки DS-K1T3xx с распознаванием лиц).
Работает напрямую по ISAPI, без MQTT, без облака, без сторонних SDK.

Слушает `/ISAPI/Event/notification/alertStream` и создаёт:

- `event.*_access_event` — событие на каждую авторизацию
  (`face_authenticated`, `card_authenticated`, `fingerprint_authenticated`,
  `face_auth_failed`, `exit_button_pressed`, либо `unknown_access_event` для
  ещё не размеченных кодов).
- `camera.*_last_access_photo` — фото, прикреплённое к последнему событию
  (если терминал его прислал; для события без фото камера очищается, чтобы
  не показывать предыдущего человека).
- `sensor.*_last_user`, `*_last_method`, `*_isapi_connection`.

Плюс событие `hikvision_acs_event` на шине HA на каждую авторизацию.

> Имена сущностей переведены, и HA строит `entity_id` из перевода для своего
> языка. В русскоязычной установке это будет `event.<устройство>_событие_доступа`,
> `camera.<устройство>_фото_последнего_доступа` и т.д. Точные id смотри в
> Developer Tools → States.

## Коды событий

Основано на официальном Hikvision ISAPI Developer Guide for Face
Recognition Terminals:

| major | minor | Событие |
|---|---|---|
| 5 | 75 | `face_authenticated` |
| 5 | 76 | `face_auth_failed` |
| 5 | 38 | `card_authenticated` |
| 5 | 113 | `fingerprint_authenticated` |
| 5 | 27 | `exit_button_pressed` |

Список в `const.py` — дополняй по мере обнаружения новых кодов у себя в
логах (`unknown_access_event` покажет атрибуты `major`/`minor`, по ним
можно добавить точную метку).

`majorEventType` у Hikvision делится на категории: 1 — тревоги, 2 —
неисправности, 3 — операции с устройством, 5 — события доступа.
Публикуются только события категории 5. Остальное к проходам людей не
относится: например, 3/121 и 3/122 терминал пишет на каждое подключение
ISAPI-клиента, то есть на каждый коннект самого Home Assistant.

Повторы отсеиваются по `serialNo`: при переподключении терминал заново
отдаёт последние записи журнала (у них `currentEvent: false`, в атрибутах
это `is_current`).

## Установка через HACS

1. HACS → Integrations → меню ⋮ → Custom repositories
2. URL этого репозитория, категория **Integration**
3. Найти "Hikvision Access Control", Download, перезапустить HA

## Настройка

Settings → Devices & Services → Add Integration → "Hikvision Access
Control". Укажи IP, порт (обычно 443), логин/пароль **отдельного
пользователя с минимальными правами** (доступ к ISAPI, чтение событий),
не используй admin.

Поддерживаются и Digest, и Basic auth — схема выбирается автоматически по
ответу устройства (Digest приоритетнее).

## Пример автоматизации

Через событие на шине (`hikvision_acs_event`) — в data лежат `event_type`,
`name`, `employee_no`, `card_no`, `verify_mode`, `major`, `minor`,
`device_time`, `serial_no`, `is_current`, `has_photo`, `entry_id`:

```yaml
automation:
  - alias: "СКУД: авторизация -> Telegram с фото"
    trigger:
      - trigger: event
        event_type: hikvision_acs_event
        event_data:
          event_type: face_authenticated
    action:
      - action: camera.snapshot
        target:
          entity_id: camera.terminal_фото_последнего_доступа
        data:
          filename: "/config/www/tmp/access_last.jpg"
      - action: telegram_bot.send_photo
        data:
          target: 123456789
          file: "/config/www/tmp/access_last.jpg"
          caption: "🔑 {{ trigger.event.data.name }}"
```

Тот же сценарий через состояние `event.*` сущности:

```yaml
automation:
  - alias: "СКУД: авторизация -> Telegram с фото"
    trigger:
      - trigger: state
        entity_id: event.terminal_событие_доступа
    condition:
      - condition: template
        value_template: >-
          {{ trigger.to_state.attributes.event_type in
             ['face_authenticated', 'card_authenticated'] }}
    action:
      - action: camera.snapshot
        target:
          entity_id: camera.terminal_фото_последнего_доступа
        data:
          filename: "/config/www/tmp/access_last.jpg"
      - action: telegram_bot.send_photo
        data:
          target: 123456789
          file: "/config/www/tmp/access_last.jpg"
          caption: >-
            🔑 {{ trigger.to_state.attributes.name }}
            ({{ trigger.to_state.attributes.event_type }})
```

## Тесты

Разбор потока и ручной Digest покрыты тестами, Home Assistant для их
запуска не нужен:

```bash
pip install -r requirements-test.txt
pytest tests -q
```

## Известные ограничения

- Не тестировалось на широком парке устройств — только на DS-K1T342MFWX.
  Другие модели линейки DS-K1T3xx, вероятно, совместимы (тот же ISAPI-стек),
  но не проверено.
- Событие без прикреплённого фото публикуется не мгновенно, а когда из
  потока приходит следующая часть (следующее событие или keep-alive
  терминала, обычно единицы секунд). Событие с фото публикуется сразу.
- Реконнект есть, но при длительном обрыве сети возможна потеря события,
  случившегося ровно в момент реконнекта.
- Сенсор `last_user` показывает имя только для успешных авторизаций; при
  отказе (`face_auth_failed`) он обнуляется.

## Лицензия

MIT
