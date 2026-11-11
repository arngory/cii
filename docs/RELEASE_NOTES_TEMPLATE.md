Бинарники `cii-<os>-<arch>` собраны статически (CGO выключен), контрольные суммы лежат в `SHA256SUMS`. Лицензии стороннего кода и данных, вошедших в бинарник, собраны в `THIRD_PARTY_LICENSES.txt`.

Файлы `*.mmdb.gz` — это снимки офлайн-баз на момент сборки, без изменений, только сжатые gzip. `cii` сам их не скачивает: распакуйте нужные в каталог данных (`cii data status` покажет путь) или выполните `cii data update`, чтобы скачать свежие базы напрямую у издателей. Источник, лицензия и дата сборки каждой базы указаны в `DATA-NOTICE.txt`.

Атрибуция:
- IP Geolocation by DB-IP (https://db-ip.com), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
- IP address data powered by IPinfo (https://ipinfo.io), [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) (если файл `ipinfo-lite.mmdb.gz` есть в релизе)
