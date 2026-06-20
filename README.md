```
   ███████╗████████╗██████╗ ██╗██╗  ██╗
   ██╔════╝╚══██╔══╝██╔══██╗██║╚██╗██╔╝
   ███████╗   ██║   ██████╔╝██║ ╚███╔╝
   ╚════██║   ██║   ██╔══██╗██║ ██╔██╗
   ███████║   ██║   ██║  ██║██║██╔╝ ██╗
   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝
        OSINT Orchestrator · they watch in the dark
```

# STRIX

[![License: MIT](https://img.shields.io/badge/License-MIT-22d3ee.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![CI](https://github.com/OWNER/strix/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/strix/actions/workflows/ci.yml)
[![Docker](https://img.shields.io/badge/docker-ready-2496ed.svg)](Dockerfile)

STRIX is a passive OSINT orchestrator. It aggregates several open-source
intelligence sources (username, email, domain, IP, phone) behind a single CLI and
produces a unified, timestamped report (JSON + Markdown + branded HTML).
**No API key is required** for the core features.

The value is not in reinventing existing tools — it is in **orchestration,
correlation and clean reporting**. STRIX calls proven tools (Maigret, Holehe) and
free public APIs (crt.sh, Shodan InternetDB, DNS, ip-api), normalizes everything
into a common schema, and emits an actionable deliverable.

## Features

- **Single CLI** over six target types: username, email, domain, IP, phone, image.
- **Image forensics**: EXIF metadata and GPS extraction via ExifTool (local file or URL).
- **Passive recon only** — STRIX observes public sources, it never attacks.
- **No API key required** for core modules (optional keys enable richer results).
- **Async orchestration** with bounded concurrency and per-module rate limiting.
- **Unified report** in JSON (source of truth), Markdown, and branded HTML.
- **Plugin architecture** — add a source by dropping one file into `modules/`.
- **Docker-first**, hardened non-root image.

## Demo

> Placeholders — replace with real captures.

![Terminal demo](docs/demo.png)

## Modules

| Module   | Target type | Sources                              | API key |
|----------|-------------|--------------------------------------|---------|
| username | username    | Maigret                              | no      |
| email    | email       | Holehe                               | no      |
| domain   | domain      | crt.sh, DNS (dnspython), WHOIS       | no      |
| ip       | ip          | Shodan InternetDB, ip-api            | no      |
| phone    | phone       | phonenumbers (offline)               | no      |
| image    | image       | ExifTool (metadata + GPS)            | no      |

## Installation

### Docker (recommended)

```bash
docker compose build
docker compose run --rm strix scan example.com --i-am-authorized
```

### Local (virtualenv)

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
strix version
```

Some modules shell out to system binaries (already bundled in the Docker image).
For local runs install them with your package manager:

```bash
# macOS
brew install exiftool whois
# Debian/Ubuntu
sudo apt install libimage-exiftool-perl whois
```

`maigret` and `holehe` are installed via pip (`pip install -e .`); `exiftool` and
`whois` are system tools. Each module degrades gracefully if its binary is absent.

## Usage

```bash
strix username paulx                 # single source-type
strix email user@example.com
strix domain example.com
strix ip 1.1.1.1
strix phone "+33612345678"
strix image photo.jpg                 # EXIF metadata + GPS (local file or URL)
strix scan example.com --i-am-authorized   # auto-detect type, run all compatible modules
strix modules                        # list available modules
strix version
```

Main options on scan commands:

| Option | Effect |
|---|---|
| `--type [auto\|username\|email\|domain\|ip\|phone\|image]` | force the target type (default `auto`) |
| `--output, -o PATH` | output directory (default `./output`) |
| `--format, -f` | subset of `json,md,html` (default: all three) |
| `--no-banner` | hide the ASCII banner |
| `--quiet, -q` | minimal output (useful in pipes/CI) |
| `--max-concurrency INT` | concurrency limit |
| `--i-am-authorized` | acknowledge the legal warning |

## Output

```
output/<target_slug>_<YYYYMMDD_HHMMSS>/
├── report.json   # serialized Report — source of truth
├── report.md     # GitHub-readable report
├── report.html   # self-contained branded report (navy/cyan)
└── raw/          # raw outputs of external tools (when produced)
```

## Legal / Ethical use

STRIX is for **authorized security research, CTF, and education only**. You are
responsible for complying with applicable laws and platform Terms of Service.
STRIX performs **passive reconnaissance only**: it queries public sources and
indexed data. It contains no active exploitation, brute-force, credential
stuffing, aggressive port scanning, or payload delivery.

## Roadmap

- [x] Phase 0 — Scaffold (models, config, CLI skeleton, plugin registry)
- [ ] Phase 1 — Core + domain/username/email modules + text report
- [ ] Phase 2 — IP/phone modules + branded HTML report
- [ ] Phase 3 — Docker (hardened, non-root)
- [ ] Phase 4 — Tests, CI, full README, network error handling

## License

MIT — see [LICENSE](LICENSE).
