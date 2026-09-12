# Настройка шлюза Telegram API для обхода блокировок в KeenGuard

## Почему Telegram не отправляет сообщения напрямую?
В сетях РФ прямой доступ к `https://api.telegram.org` заблокирован на уровне ТСПУ / DPI провайдеров. При попытке отправить запрос возникает ошибка `ConnectTimeout` (таймаут подключения).

Для надежной доставки уведомлений в KeenGuard встроены два штатных механизма обхода:
1. **Шлюз Cloudflare Worker (рекомендуется — бесплатно, быстро, не требует запущенного VPN)**;
2. **Локальный или внешний HTTP/SOCKS5 прокси** (Xray, V2Ray, Sing-box, Tor, Shadowsocks).

---

## Вариант 1: Бесплатный шлюз Cloudflare Worker (за 2 минуты)

Cloudflare предоставляет бесплатный тариф Workers (до 100 000 запросов в день), чего с избытком хватает для системных алертов. Cloudflare имеет прямой доступ к Telegram API и не блокируется провайдерами.

### Шаг 1: Создание воркера в Cloudflare
1. Зарегистрируйтесь или войдите в панель управления [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. В боковом меню выберите **Workers & Pages** -> **Overview**.
3. Нажмите кнопку **Create Application** (или **Create Worker**).
4. Задайте имя воркеру, например: `keenguard-tg-proxy`.
5. Нажмите **Deploy**.

### Шаг 2: Вставка кода прокси
1. На странице созданного воркера нажмите кнопку **Edit code**.
2. Удалите стандартный шаблон и вставьте следующий скрипт:

```javascript
export default {
  async fetch(request) {
    const url = new URL(request.url);
    url.hostname = 'api.telegram.org';
    return fetch(new Request(url, request));
  }
};
```

3. Нажмите **Save and Deploy** (или **Deploy**) в правом верхнем углу.

### Шаг 3: Подключение к KeenGuard
1. Скопируйте полученный URL вашего воркера. Он имеет вид:
   `https://keenguard-tg-proxy.<ваш-аккаунт>.workers.dev`
2. Откройте веб-интерфейс **KeenGuard** (`http://127.0.0.1:9989`).
3. В левой боковой панели перейдите в подраздел: **Настройки** -> **Telegram & Тревоги**.
4. Вставьте скопированный URL в поле **«Шлюз Telegram API (Cloudflare Worker)»**.
5. Убедитесь, что:
   - Включен чекбокс **«Включить оповещения в Telegram»**;
   - Заполнены **Bot Token** и **Chat ID**.
6. Нажмите **«Отправить тест в Telegram»**. В чат должно мгновенно прийти тестовое сообщение.
7. Нажмите **«Сохранить параметры Telegram»**.

---

## Вариант 2: Использование локального SOCKS5 / HTTP прокси

Если на вашем сервере, ПК или роутере уже работает клиент обхода блокировок (например, V2Ray / Xray / Sing-box / Tor / Shadowsocks):

1. В поле **«Прокси (опционально)»** укажите адрес в формате:
   - Для SOCKS5 без авторизации: `socks5://127.0.0.1:10808`
   - Для SOCKS5 с паролем: `socks5://user:password@192.168.1.1:1080`
   - Для HTTP-прокси: `http://127.0.0.1:8080`
2. Поле **«Шлюз Telegram API»** оставьте пустым (будет использоваться `https://api.telegram.org`).
3. Нажмите **«Отправить тест в Telegram»** и затем сохраните настройки.

---

## Диагностика и ручной тест через CLI
Проверить доставку можно одной командой из терминала:
```powershell
.\venv\Scripts\python.exe -c "import asyncio; from keenguard.core.notifier import notifier; asyncio.run(notifier.send_test_message('ВАШ_ТОКЕН', 'ВАШ_CHAT_ID', api_url='https://keenguard-tg-proxy.ваш-аккаунт.workers.dev'))"
```
