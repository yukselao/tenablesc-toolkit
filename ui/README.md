# Nessus Compare UI

Bootstrap tabanlı, iki tarama sonucunu karşılaştıran web arayüzü. İki çalışma modu var:

1. **Compare Nessus Scans** — iki `.nessus` dosyasını (First / Last) yükleyip karşılaştırır.
2. **Compare Scan Results** — Tenable Security Center'daki scan result'ların bulgularını
   (`/rest/analysis`, `tool=listvuln`) doğrudan API'den çekip karşılaştırır (dosya yüklemeden).
3. **Security Center Settings** — SC URL + Access/Secret Key (DB'de saklanır, kimlik doğrulama yok).

Her iki modda da sonuç **CSV** / **HTML** olarak export edilebilir ve **Print / PDF** alınabilir.

## Analiz mantığı

| Tablo | Kural |
|-------|-------|
| **Newly Detected Hosts** | First scan'de **olmayıp** Last scan'de **olan** host |
| **New Detected Ports** | Her iki scan'de de olan bir host'ta Last scan'de **yeni açılan** port |
| **Unreachable Hosts** | First scan'de **olup** Last scan'de **olmayan** host |

Açık portlar her `ReportHost` içinde iki kaynaktan çıkarılır:
`enumerated-ports-<port>-<proto>` tag'ları (Host Discovery) ve sıfır olmayan
`<ReportItem port="...">` değerleri (full scan).

## Stack

- **web** — `php:8.3-apache` + Bootstrap 5 (CDN), `pdo_mysql`, SC için curl
- **db** — `mariadb:11`, analiz geçmişi (`analyses`) + SC ayarları (`settings`)
- Port: **http://localhost:8091/**

## Security Center bağlantısı

`Compare Scan Results` çalışmadan önce **Settings**'ten SC bilgileri girilir.
Akış: `GET /rest/scanResult` ile scan result listesi → seçilen First/Last için
`POST /rest/analysis` (`tool=listvuln`, `sourceType=individual`, `scanID`) sayfalı çekilir →
her satırdaki `ip`/`port`/`protocol` host→port haritasına dönüştürülür → aynı karşılaştırma
motoruyla (NessusParser::compare) 3 tablo üretilir.

> **Docker Desktop notu:** SC bu makinede/loopback IP'sinde (ör. `192.168.1.62`) çalışıyorsa
> container o IP'ye ulaşamaz. SC URL'sini `https://host.docker.internal:8443` olarak girin.

## Kullanım

```bash
./start.sh        # build + up, hazır olunca URL'i yazar
./stop.sh         # durdur (veri korunur)
./reset-db.sh     # analiz geçmişini temizle (TRUNCATE)
./reset-db.sh --hard   # DB volume'unu komple sil ve yeniden kur
```

## Test verisi

```bash
python3 ../sample-data/compare-scenarios/generate_samples.py
```
`first-scan.nessus` + `last-scan.nessus` üretir; üç senaryoyu da tetikler:
yeni host `10.10.10.200`, yeni portlar `10.10.10.11` (8080/tcp, 3389/tcp),
unreachable `10.10.10.55`.
