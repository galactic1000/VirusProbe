# VirusProbe

An efficient malware scanning tool powered by VirusTotal. Scan files, directories, or SHA-256 file hashes with both CLI and GUI interfaces. Features intelligent caching, concurrent scanning, and automatic file upload for undetected samples.

## Requirements

- Python 3.11+
- VirusTotal API key

## Installation

### Option 1: Download Pre-built Executables (Recommended)

Download the latest executables for your platform from [GitHub Releases](https://github.com/galactic1000/VirusProbe/releases):
- `VirusProbe-CLI` - Command-line interface
- `VirusProbe-GUI` - Graphical interface

Available for Windows, Linux, and macOS. No Python installation required.

### Option 2: Run from Source

CLI dependencies:

```bash
pip install -r requirements-cli.txt
```

GUI dependencies:

```bash
pip install -r requirements-gui.txt
```

## Quickstart

### Using Executables

**CLI:**

```bash
VirusProbe-CLI --api-key "your_api_key_here" --save-api-key
VirusProbe-CLI -s 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
```

**GUI:**

1. Run `VirusProbe-GUI`
2. Set API key in the GUI
3. Add files and/or SHA-256 hashes
4. Click `Scan`
5. Generate report after scan completes

### Running from Source

**CLI:**

```bash
python cli.py --api-key "your_api_key_here" --save-api-key
python cli.py -s 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
```

**GUI:**

```bash
python gui.py
```

## Features

**Scanning**
- Scan individual files, whole directories (with optional recursion), or bare SHA-256 file hashes
- Mix directory scans with extra hash inputs in a single run
- Concurrent scanning with a configurable worker count and per-minute rate limit

**Upload**
- Optionally upload files with no VirusTotal record and wait for real engine verdicts
- Three upload modes: `never` (default), `manual` (toolbar `Upload` button in GUI), `auto` (automatic during scan)
- CLI `--upload-filter` accepts glob patterns to limit which undetected files get uploaded

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

## CLI Usage

With executable:

```bash
VirusProbe-CLI [options]
```

Or from source:

```bash
python cli.py [options]
```

### Options

| Flag | Description |
|---|---|
| `-f, --file, --files` | One or more file paths to scan |
| `-s, --hash, --hashes` | One or more SHA-256 hashes to scan |
| `-d, --directory, --dir` | Scan all files in a directory |
| `-r, --recursive` | Recurse subdirectories (directory mode only) |
| `-u, --upload` | Upload files not found in VirusTotal and wait for analysis results (uses extra API quota) |
| `--upload-filter GLOB [GLOB ...]` | Only upload files matching these globs (requires `--upload`): filename `*.exe`; path `*/src/*.dll` (matched against resolved absolute paths). |
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

> **Note:** Replace `VirusProbe-CLI` with `python cli.py` if running from source.

Scan files:

```bash
VirusProbe-CLI -f file1.exe file2.dll
```

Scan hashes:

```bash
VirusProbe-CLI -s HASH1 HASH2
```

Scan directory recursively:

```bash
VirusProbe-CLI -d /path/to/folder -r
```

Generate report:

```bash
VirusProbe-CLI -f sample.exe -o --format md
```

Custom rate limit:

```bash
VirusProbe-CLI -d /path/to/folder --requests-per-minute 10
```

Upload with file filter:

```bash
VirusProbe-CLI -d /path/to/folder --upload --upload-filter "*.exe" "*.dll"
```

## GUI Usage

- **Set API Key**: Store/remove key in `.env`
- **Add Item**: Add files, single SHA-256 hash, or multiple hashes (one per line)
- **Drag-and-drop**: Accepts files directly
- **Advanced Settings**: Configure workers (1-50), rate limit, and upload mode (never/manual/auto)
  - Manual mode: `Upload` button appears in toolbar - select `Undetected` rows and click to upload
  - Auto mode: Undetected files upload automatically during scan
  - Settings persist to `.env`
- **Scan/Cancel**: `Scan` button becomes `Cancel` during active scans
- **Generate Report**: Export results in JSON, CSV, TXT, or Markdown
- **Clear Cache**: Remove locally cached scan results

## Cache & Configuration

VirusProbe uses local SQLite caching (`cache/vt_cache.db`) and stores settings in `.env`. Both CLI and GUI can clear the cache.

Supported environment variables: `VT_API_KEY`, `VIRUSTOTAL_API_KEY`, `VT_REQUESTS_PER_MINUTE`, `VT_WORKERS`.

## Verdict Criteria

Results are classified as: `Malicious`, `Suspicious`, `Clean`, `Undetected`, or `Error` based on VirusTotal engine counts. Uploaded items are prefixed with `Uploaded -`.

## Reports

Supported formats:

- `json`
- `csv`
- `txt`
- `md`

Reports include summary counts and per-item scan details.

## Testing

For developers: install test dependencies and run tests with pytest:

```bash
pip install -r requirements-test.txt
pytest -q
```

Tests cover CLI, caching, scanning, uploading, rate limiting, and reporting.

