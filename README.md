# VirusProbe

VirusProbe scans file paths, directories, and SHA-256 hashes with VirusTotal.
It provides both a CLI and a Tkinter GUI, with local caching to reduce repeat API calls.

## Features

**Scanning**
- Scan individual files, whole directories (with optional recursion), or bare SHA-256 hashes
- Mix directory scans with extra hash inputs in a single run
- Concurrent scanning with a configurable worker count and per-minute rate limit

**Upload**
- Optionally upload files with no VirusTotal record and wait for real engine verdicts
- Three upload modes: `never` (default), `manual` (Upload button per row in GUI), `auto` (automatic during scan)
- CLI `--upload-filter` accepts glob patterns to limit which unknown files get uploaded

**Results & Reporting**
- Verdicts: `Malicious`, `Suspicious`, `Clean`, `Undetected`, `Error`
- Export scan reports in `json`, `csv`, `txt`, or `md`
- Two-level result cache: in-memory LRU + SQLite (uploaded results cached too)

**CLI**
- Streaming per-item output as results arrive
- Graceful Ctrl+C cancellation (exits with code `130`)
- Save, load, and remove API key via `.env`

**GUI**
- Drag-and-drop file support
- Live scan progress bar and per-row status updates
- Advanced settings dialog (workers, rate limit, upload mode) persisted to `.env`

## Requirements

- Python 3.11+
- VirusTotal API key

## Installation

CLI dependencies:

```bash
pip install -r requirements-cli.txt
```

GUI dependencies:

```bash
pip install -r requirements-gui.txt
```

Testing dependencies:

```bash
pip install -r requirements-test.txt
```

## Quickstart

### CLI

1. Set your API key for the current shell:

```bash
export VT_API_KEY="your_api_key_here"
```

2. Or save it once to project `.env`:

```bash
python cli.py --api-key "your_api_key_here" --save-api-key
```

3. Run a scan:

```bash
python cli.py -s 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
```

### GUI

1. Launch GUI:

```bash
python gui.py
```

2. In the app:

- Set API key
- Add files and/or SHA-256 hashes
- Click `Scan`
- Generate report after scan completes

## CLI Usage

Run:

```bash
python cli.py [options]
```

### Input rules

- Use `--directory` or `--file`, not both.
- `--directory` can be combined with `--hash`.
- `--recursive` is valid only with `--directory`.
- At least one scan input is required: `--directory`, `--file`, or `--hash`.
- Invalid file inputs are grouped under `INPUT WARNINGS` and skipped.

### Options

| Flag | Description |
|---|---|
| `-f, --file, --files` | One or more file paths to scan |
| `-s, --hash, --hashes` | One or more SHA-256 hashes to scan |
| `-d, --directory, --dir` | Scan all files in a directory |
| `-r, --recursive` | Recurse subdirectories (directory mode only) |
| `-u, --upload` | Upload files not found in VirusTotal and wait for analysis results (uses extra API quota) |
| `--upload-filter GLOB [GLOB ...]` | Only upload files matching these glob patterns (requires `--upload`). Patterns without path separators match filename only (e.g. `*.exe`); patterns with separators match the full path (e.g. `src/*.dll`) |
| `-o, --output [OUTPUT]` | Write report to file; when used without value, auto-generates `scan_report_YYYYMMDD_HHMMSS.<format>` |
| `--format {json,csv,txt,md}` | Report format for `--output` (default: `json`) |
| `--requests-per-minute N` | Max VirusTotal API requests per minute (default: `4`, `0` = unlimited) |
| `--workers WORKERS` | Concurrent scan workers (default: matches `--requests-per-minute`, minimum: `1`) |
| `--api-key API_KEY` | VirusTotal API key for this run |
| `--save-api-key` | Save `--api-key` into `.env` |
| `--clear-api-key` | Remove saved API key from `.env` |
| `--clear-cache` | Clear local SQLite cache |
| `--version` | Print version and exit |
| `-h, --help` | Show help and exit |

### CLI examples

Scan files:

```bash
python cli.py -f file1.exe file2.dll
```

Scan hashes:

```bash
python cli.py -s HASH1 HASH2
```

Scan directory:

```bash
python cli.py -d /path/to/folder
```

Scan directory recursively:

```bash
python cli.py -d /path/to/folder -r
```

Scan directory plus hashes:

```bash
python cli.py -d /path/to/folder -s HASH1 HASH2
```

Generate report (explicit path):

```bash
python cli.py -f sample.exe -o reports/scan.json --format json
```

Generate report (auto filename):

```bash
python cli.py -f sample.exe -o --format md
```

Scan with a premium API key (no rate limit):

```bash
python cli.py -d /path/to/folder --requests-per-minute 0
```

Scan with a custom rate limit:

```bash
python cli.py -d /path/to/folder --requests-per-minute 10
```

Upload unknown files (not found in VirusTotal):

```bash
python cli.py -f sample.exe --upload
```

Upload only `.exe` and `.dll` files that are unknown:

```bash
python cli.py -d /path/to/folder --upload --upload-filter "*.exe" "*.dll"
```

Upload unknown files inside a specific subdirectory:

```bash
python cli.py -d /path/to/folder --upload --upload-filter "suspicious/*.bin"
```

Clear cache only:

```bash
python cli.py --clear-cache
```

## GUI Usage

- `Set API Key` masks and stores/removes key in `.env`.
- `Add Item` menu supports:
  - Add file(s)
  - Add SHA-256 hash
  - Add multiple SHA-256 hashes (one per line)
- Drag-and-drop accepts files.
- Duplicate queued items are skipped.
- `Advanced...` opens the Advanced Scan Settings dialog:
  - **Workers**: concurrent scan threads (default: `4`, range: `1`-`50`)
  - **Req/min**: VirusTotal API rate limit (default: `4`, `0` = unlimited for premium keys)
  - **Enable upload to VirusTotal for unknown files** (uses extra API quota): when checked, files not found in VirusTotal can be uploaded for scanning
    - **Auto-upload all unknown items**: when checked, uploads happen automatically during the scan (`auto` mode); when unchecked, an `Upload` button appears after the scan so you can upload selected rows manually (`manual` mode)
  - Settings are saved to `.env` on Apply and restored on next launch.
- `Scan` runs all queued items.
- During an active scan, `Scan` changes to `Cancel` so you can stop remaining queued work.
- When upload mode is `manual` and the scan finds undetected file rows, an `Upload` button appears in the toolbar. Select one or more `Undetected` file rows and click `Upload` to submit them to VirusTotal.
- Bottom-right progress bar tracks completed items for the current scan.
- `Generate Report...` is enabled after the first completed scan.
- Report dialog supports report name, format, and destination folder.
- After generation, GUI offers `Open Report` and `Open Folder`.
- `Clear Cache` clears the local SQLite cache.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `VT_API_KEY` | VirusTotal API key | - |
| `VIRUSTOTAL_API_KEY` | Alternative name for the API key (checked second) | - |
| `VT_REQUESTS_PER_MINUTE` | Max VirusTotal API calls per 60-second window. `0` = unlimited (premium keys). GUI Advanced dialog writes this on Apply. | `4` |
| `VT_WORKERS` | Concurrent scan threads. Must be `>= 1`. GUI Advanced dialog writes this on Apply. | `4` |
| `VT_UPLOAD_UNKNOWN` | Upload mode for files not found in VirusTotal. `never` = disabled, `manual` = Upload button shown after scan, `auto` = upload automatically during scan. GUI Advanced dialog writes this on Apply. | `never` |

Example `.env`:

```env
VT_API_KEY=your_api_key_here
VT_REQUESTS_PER_MINUTE=4
VT_WORKERS=4
VT_UPLOAD_UNKNOWN=never
```

## API Key Resolution

Resolution order:

1. CLI `--api-key`
2. Environment variables: `VT_API_KEY`, `VIRUSTOTAL_API_KEY`
3. Project `.env`

## Cache

VirusProbe uses two layers:

1. In-memory LRU cache (per process, default max entries: `512`)
2. SQLite cache at `cache/vt_cache.db` (WAL mode)

SQLite defaults:

- Expiry: 7 days
- Max rows: 10,000

When WAL is active, `vt_cache.db-wal` and `vt_cache.db-shm` are expected.

Both CLI `--clear-cache` and GUI `Clear Cache` clear:

- SQLite rows
- WAL checkpoint/truncate
- In-memory cache for that running process

## Verdict Criteria

Per item classification is based on VirusTotal engine counts:

- `Malicious`: `malicious >= 10`
- `Suspicious`: `malicious >= 1` (but `< 10`), or `suspicious >= 3`
- `Clean`: `malicious == 0` and `suspicious < 3` with known result
- `Undetected`: VirusTotal has no record for that SHA-256 hash
- `Error`: invalid input or runtime/API error

Items uploaded to VirusTotal are prefixed with `Uploaded -` in the status column (e.g. `Uploaded - Clean`).

Displayed engine counters:

- `malicious`
- `suspicious`
- `harmless`
- `undetected`

## Reports

Supported formats:

- `json`
- `csv`
- `txt`
- `md`

Reports include summary counts and per-item scan details.

## Testing

Run all tests:

```bash
pytest -q
```

`pytest.ini` is included, so running from repo root works without manually setting `PYTHONPATH`.

Run one module:

```bash
pytest -q tests/test_service.py
```

Current automated coverage:

- `tests/test_cache.py`: cache behavior, cleanup, row caps, LRU
- `tests/test_service_scan.py`: scan orchestration, hash validation, API error mapping, mixed scan paths
- `tests/test_service_upload.py`: upload flow, polling, filter logic, size thresholds
- `tests/test_service_rate_limit.py`: rate limiter behavior
- `tests/test_cli_parser.py`: parser and flag behavior
- `tests/test_cli_behavior.py`: CLI runtime behavior and admin paths
- `tests/test_reporting.py`: report writers and output path handling

GUI interactions are not currently covered by automated tests.

## Project Structure

```text
VirusProbe/
|-- cli.py
|-- gui.py
|-- cli/
|   |-- app.py
|   `-- display.py
|-- gui/
|   |-- app.py
|   |-- controllers.py
|   |-- dialogs.py
|   `-- view.py
|-- common/
|   |-- __init__.py
|   |-- cache.py
|   |-- env.py
|   |-- rate_limit.py
|   |-- reporting.py
|   |-- service.py
|   |-- service_scan.py
|   `-- service_upload.py
|-- cache/
|   `-- vt_cache.db
|-- tests/
|   |-- test_cache.py
|   |-- test_cli_behavior.py
|   |-- test_cli_parser.py
|   |-- test_reporting.py
|   |-- test_service_scan.py
|   |-- test_service_upload.py
|   `-- test_service_rate_limit.py
|-- requirements-cli.txt
|-- requirements-gui.txt
|-- requirements-test.txt
`-- README.md
```

