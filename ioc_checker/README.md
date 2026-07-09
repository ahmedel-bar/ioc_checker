# IOC Checker — Threat Intelligence Aggregator CLI

A single-command CLI tool for SOC analysts and threat hunters. Give it any
indicator of compromise (IP, domain, URL, or hash) and it queries multiple
threat intelligence providers concurrently, then rolls the results up into
one risk score and verdict.

```
python ioc_checker.py 8.8.8.8
```

## Providers

Providers are queried dynamically based on the detected IOC type — only
providers that actually support that type are queried and shown.

| Provider        | Env Variable              | Key required | Supported IOC Types                  |
|-----------------|----------------------------|--------------|----------------------------------------|
| VirusTotal (v3) | `VT_API_KEY`               | Yes          | IPv4, Domain, URL, MD5, SHA1, SHA256   |
| AlienVault OTX  | `OTX_API_KEY`               | Yes          | IPv4, Domain, URL, MD5, SHA1, SHA256   |
| ThreatFox       | `THREATFOX_API_KEY`         | Yes          | IPv4, Domain, URL, MD5, SHA1, SHA256   |
| AbuseIPDB       | `ABUSEIPDB_API_KEY`         | Yes          | IPv4 only                              |
| URLhaus         | `URLHAUS_API_KEY`           | No (public)  | URL only                               |
| MalwareBazaar   | `MALWAREBAZAAR_API_KEY`     | No (public)  | MD5, SHA1, SHA256                      |
| Pulsedive       | `PULSEDIVE_API_KEY`         | Yes (free)   | IPv4, Domain, URL                      |

Provider selection is driven entirely by each provider's own
`SUPPORTED_TYPES` declaration (see `providers/manager.py`) — there are no
hardcoded if/else chains deciding which provider runs for which IOC type.
To add a new provider: create `providers/<name>.py` implementing
`BaseProvider`, add its key to `config.py`, and register it in
`providers/manager.py`.

> Note: abuse.ch (URLhaus, MalwareBazaar, ThreatFox) now requires an
> Auth-Key for most endpoints, even ones historically documented as fully
> public. If you see `403 Forbidden` from these providers, add an
> abuse.ch Auth-Key to the relevant `.env` entry.

## Supported IOC Types

Type is auto-detected — you never specify it:

- IPv4
- Domain
- URL
- MD5 / SHA1 / SHA256 file hashes

## Installation

```bash
git clone <this-repo>
cd ioc_checker
pip install -r requirements.txt
cp .env.example .env
# then edit .env and add your API keys
```

## Usage

```bash
python ioc_checker.py 8.8.8.8
python ioc_checker.py google.com
python ioc_checker.py https://evil.com/login
python ioc_checker.py 44d88612fea8a8f36de82e1278abb02f
```

Sample output includes:

1. ASCII banner + version
2. IOC info panel (value, detected type, length, timestamp)
3. Transient progress spinner while providers are queried concurrently
   (cleared automatically once scanning finishes)
4. Results table (per-provider verdict, confidence, and details)
5. Overall Assessment panel (risk score, sources queried/matched, recommendation)
6. API warnings section - only appears if one or more providers failed
   during this scan (replaces the old always-on API status table)
7. Footer (execution time, providers used)

## API Health / Warnings

There is no longer a persistent "API Status" table shown on every run. If
every queried provider succeeds, nothing extra is printed. If a provider
fails (missing/invalid key, rate limit, timeout, unexpected response), a
compact `⚠ API WARNINGS` panel appears after the Overall Assessment,
listing only the providers that actually failed and why.

## Risk Scoring

| Signal                        | Points |
|--------------------------------|--------|
| VirusTotal malicious            | +40    |
| VirusTotal suspicious            | +20    |
| AlienVault OTX has pulses        | +30    |
| ThreatFox has a match             | +30    |
| AbuseIPDB score ≥ 75              | +40    |
| AbuseIPDB score 25–74               | +20    |
| URLhaus URL online                  | +30    |
| URLhaus URL offline                   | +15    |
| MalwareBazaar has a match               | +30    |
| Pulsedive risk critical                  | +40    |
| Pulsedive risk high                      | +30    |
| Pulsedive risk medium                    | +20    |
| Pulsedive risk low                       | +10    |

| Score range | Overall Assessment |
|-------------|----------------------|
| 0–20        | CLEAN                |
| 21–50       | SUSPICIOUS           |
| 51–100      | HIGH RISK            |

## Project Layout

```
ioc_checker/
├── ioc_checker.py       # CLI entry point
├── config.py            # .env / API key loading
├── detector.py          # IOC type detection
├── utils.py             # Logging + unified ProviderResult/Verdict types
├── ui.py                # Rich-based presentation layer
├── requirements.txt
├── .env.example
└── providers/
    ├── __init__.py       # BaseProvider interface (+ SUPPORTED_TYPES)
    ├── manager.py        # Provider registry / dynamic selection
    ├── virustotal.py
    ├── otx.py
    ├── threatfox.py
    ├── abuseipdb.py
    ├── urlhaus.py
    ├── malwarebazaar.py
    └── pulsedive.py
```

## Error Handling

If a provider fails (bad key, timeout, rate limit, unexpected response), its
row simply shows `ERROR` with a short reason — the scan continues for the
remaining providers and the tool never crashes.

## Logging

All requests and errors are logged to `ioc_checker.log` in the working
directory.


## ScreenShots While Working

- Hash
<img width="1180" height="870" alt="md5 hash" src="https://github.com/user-attachments/assets/071a7b3f-a317-4752-9ab3-4a40d2ff7e76" />


- Hash
<img width="1907" height="897" alt="sha256 hash" src="https://github.com/user-attachments/assets/ac8c031d-46df-4e01-acf1-486f6079b86d" />


- Domain
<img width="1905" height="812" alt="domain" src="https://github.com/user-attachments/assets/26d15830-5f36-4500-afc2-5a6775bd5cde" />

- URL
<img width="1907" height="892" alt="url" src="https://github.com/user-attachments/assets/d03a782d-5ab8-4802-9be0-7e44839e9079" />

- ip
<img width="1907" height="930" alt="ip" src="https://github.com/user-attachments/assets/33b459c6-cbb0-483b-a35e-c3f0b0a723d1" />

- File Path
<img width="1762" height="862" alt="file-path" src="https://github.com/user-attachments/assets/e45c7139-ac04-440d-b197-43739f9c56ed" />

