# Благодарности

cii написан с нуля на Go, но идеи, наборы проверок и подходы взяты из этих проектов. Если фрагменты логики переносятся напрямую, авторство сохраняется в соответствии с их лицензиями.

| Проект | Лицензия | Роль в cii |
|---|---|---|
| [lmc999/RegionRestrictionCheck](https://github.com/lmc999/RegionRestrictionCheck) | AGPL-3.0 | каталог региональных проверок сервисов |
| [xykt/IPQuality](https://github.com/xykt/IPQuality) | AGPL-3.0 | репутация IP, DNSBL, проба почтового порта |
| [vernette/ipregion](https://github.com/vernette/ipregion) | MIT | мнения GeoIP-провайдеров и сервисов о регионе, формат JSON |
| [vernette/censorcheck](https://github.com/vernette/censorcheck) | MIT | проверки DNS, DPI и Telegram |
| [masonr/yet-another-bench-script](https://github.com/masonr/yet-another-bench-script) | WTFPL | набор бенчмарков, iperf3-серверы |
| [teddysun/across](https://github.com/teddysun/across) (bench.sh) | Apache-2.0 | формат сводки о системе и скорости |
| [itdoginfo/russian-iperf3-servers](https://github.com/itdoginfo/russian-iperf3-servers) | — | подсказка для российского списка iperf3 |

## Данные

- IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0
- IP address data powered by IPinfo (https://ipinfo.io), CC BY-SA 4.0
- This product includes GeoLite2 data created by MaxMind (https://www.maxmind.com) — только при загрузке пользователем со своим ключом
- Названия стран — Unicode CLDR (https://cldr.unicode.org), Unicode License v3
- Коды аэропортов — OurAirports (https://ourairports.com), Public Domain

## Библиотеки

- [oschwald/maxminddb-golang](https://github.com/oschwald/maxminddb-golang) — ISC
- [go-yaml/yaml](https://github.com/go-yaml/yaml) — MIT / Apache-2.0
- [golang.org/x/net, sys, term, text](https://cs.opensource.google/go/x) — BSD-3-Clause
- стандартная библиотека и рантайм Go — BSD-3-Clause

Полные тексты лицензий всего, что входит в бинарник, включая Unicode License v3 для данных CLDR, собираются при выпуске в файл `THIRD_PARTY_LICENSES.txt`. Он прикладывается к релизу и кладётся в пакеты deb, rpm и apk. Локально его можно собрать командой `go run ./tools/notices licenses THIRD_PARTY_LICENSES.txt`.
