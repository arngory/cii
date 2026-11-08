Бинарники `cii-<os>-<arch>` собраны статически (CGO выключен), контрольные суммы лежат в `SHA256SUMS`.

Файлы `*.mmdb.gz` — это снимки офлайн-баз на момент сборки. `cii` сам их не скачивает: распакуйте нужные в каталог данных (`cii data status` покажет путь) или выполните `cii data update`, чтобы скачать свежие базы напрямую у издателей.

Атрибуция:
- IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0
- IP address data powered by IPinfo (https://ipinfo.io), CC BY-SA 4.0 (если файл `ipinfo-lite.mmdb.gz` есть в релизе)
