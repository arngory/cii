# Offline data

[Русская версия](../DATA_SOURCES.md)

| ID | What | Licence | Key | May be put in releases |
|---|---|---|---|---|
| `dbip-country-lite` | DB-IP IP to Country Lite | CC BY 4.0 | no | yes |
| `dbip-asn-lite` | DB-IP IP to ASN Lite | CC BY 4.0 | no | yes |
| `dbip-city-lite` | DB-IP IP to City Lite (~130 MB) | CC BY 4.0 | no | yes |
| `ipinfo-lite` | IPinfo Lite (country + ASN) | CC BY-SA 4.0 | `ipinfo_token` | yes, with attribution |
| `geolite2-country`, `geolite2-city`, `geolite2-asn` | MaxMind GeoLite2 | GeoLite2 EULA | `maxmind_account_id` + `maxmind_license_key` | **no** |

How downloading works:

- Downloading is explicit only: `cii data update [ID...]`. Only the publisher's hosts are contacted (`cii data update --plan` shows them).
- DB-IP publishes its databases monthly. If the file for the current month is not there yet, the previous month is taken.
- The downloaded file is validated as a correct MaxMind DB, and only then atomically replaces the old one.
- `manifest.json` records the URL without secrets, the download date, the build date of the database, the type, the size and the sha256.

The attribution lines that the licences require are printed by cii in every report where the corresponding database was used.

## Built-in reference data

| File | Source | Licence | Purpose |
|---|---|---|---|
| `internal/refdata/countries.tsv` | [Unicode CLDR](https://github.com/unicode-org/cldr-json), English territory names | Unicode License v3, the text is in `internal/refdata/LICENSE-unicode.txt` | country names in the report, parsing of the registrant's address in RDAP |
| `internal/refdata/iata.tsv` | [OurAirports](https://ourairports.com/data/) | Public Domain | the country of a CDN location by IATA code |

The files are generated during development with the `go generate ./internal/refdata` command and are committed; at run time cii does not fetch them from anywhere.

## Sets of the `risk` module

The official ranges of AWS, GCP, Oracle, Cloudflare and DigitalOcean, the list of Tor exit nodes, Spamhaus DROP and the PeeringDB network types are downloaded by the same `cii data update` command and stored separately, in `data/risk/`. The principle is the same: the original source only, explicit update only, sha256 in the manifest. They are not put into releases. The list, terms of use and format are in [RISK_CHECKS.md](RISK_CHECKS.md).

## Release snapshots

The release workflow can attach `*.mmdb.gz` database snapshots to a release: DB-IP Lite always, IPinfo Lite if the `IPINFO_TOKEN` secret is set in the repository. cii itself does not download these files: they are unpacked by hand if you need to work with no requests to the publishers at all.

Both licences (CC BY 4.0 and CC BY-SA 4.0) allow copies to be distributed provided that the author, the licence with a link, the disclaimer of warranties and the information about changes are given together with them. The workflow writes this information to `DATA-NOTICE.txt` next to the databases, so the attribution does not depend on the text of the release description. The databases are published unmodified: gzip compression is a change of format, not an adaptation, so IPinfo's ShareAlike condition does not extend to the cii code. cii only reads the database at run time. GeoLite2 never goes into a release (the MaxMind EULA forbids redistribution). The lists of the risk module (Tor, cloud ranges, Spamhaus DROP, PeeringDB) are not attached either: each has its own terms, and the user downloads them on their own.
