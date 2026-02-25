# VirusProbe

VirusProbe scans files, directories, and SHA-256 hashes against VirusTotal. It includes both a CLI and a Tkinter GUI, and uses local caching to reduce repeated API calls.

## Requirements

- Python 3.11+
- VirusTotal API key

## Install

### CLI

```bash
pip install -r requirements-cli.txt
```

### GUI

```bash
pip install -r requirements-gui.txt
```

## Quick Start

### 1) Set API key (bash)

```bash
export VT_API_KEY="your_api_key_here"
```

Or save once via CLI:

```bash
python cli.py --api-key "your_api_key_here" --save-api-key
```

### 2) Run scan (CLI)

```bash
python cli.py -h 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
```

### 3) Launch GUI

```bash
python gui.py
```

## CLI Usage

```bash
python cli.py [options]
```

### Input rules

- Use `--directory` or `--file`, not both.
- `--directory` can be combined with `--hash`.
- `--recursive` is valid only with `--directory`.
- At least one scan input is required: `--directory`, `--file`, or `--hash`.

### Options

| Flag | Description |
|---|---|
| `-f, --file, --files` | One or more file paths to scan |
| `-h, --hash, --hashes` | One or more SHA-256 hashes to scan |
| `-d, --directory, --dir` | Scan all files in a directory |
| `-r, --recursive` | Recurse subdirectories (directory mode only) |
| `-o, --output` | Report output path |
| `--format` | Report format: `json`, `csv`, `txt`, `md` (default `json`) |
| `--workers` | Concurrent scan workers (default `4`, minimum `1`) |
| `--api-key` | API key override for this run |
| `--save-api-key` | Save `--api-key` into `.env` |
| `--clear-api-key` | Remove saved API key from `.env` |
| `--clear-cache` | Clear local SQLite cache |
| `--help` | Show help |

### Examples

Scan files:

```bash
python cli.py -f file1.exe file2.dll
```

Scan hashes:

```bash
python cli.py -h HASH1 HASH2
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
python cli.py -d /path/to/folder -h HASH1 HASH2
```

Generate report:

```bash
python cli.py -f sample.exe -o reports/scan.json --format json
```

Clear cache only:

```bash
python cli.py --clear-cache
```

## GUI Usage

- **Set API Key** button stores/removes key in `.env` automatically.
- **Add Item** menu:
  - Add File(s)
  - Add SHA-256 Hash
  - Add Multiple SHA-256 Hashes (one per line)
- Drag-and-drop supports files.
- Duplicate items are skipped.
- **Scan** processes queued items.
- **Generate Report** is always visible and becomes enabled after at least one completed scan result.
- Report dialog lets you choose:
  - report name
  - format (`json`, `csv`, `txt`, `md`)
  - destination folder
- After report generation, dialog provides:
  - Open Report
  - Open Folder
- **Clear Cache** clears local SQLite cache.

## API Key Resolution Order

1. CLI `--api-key`
2. Environment variables: `VT_API_KEY`, `VIRUSTOTAL_API_KEY`
3. Project `.env` file

Example `.env`:

```env
VT_API_KEY=your_api_key_here
```

## Cache

VirusProbe uses two cache layers:

1. In-memory LRU cache (per process, default max entries: `512`)
2. SQLite cache at `cache/vt_cache.db` (WAL mode enabled)

SQLite defaults:

- Expiry: 7 days
- Max rows: 10,000

When WAL is active, `vt_cache.db-wal` and `vt_cache.db-shm` are expected.

Both CLI `--clear-cache` and GUI **Clear Cache** clear:

- SQLite cache rows
- WAL checkpoint/truncate
- in-memory cache for that running process

## Verdict Criteria

Per item, threat classification is based on VirusTotal malicious engine count:

- `Malicious`: malicious >= 10
- `Suspicious`: malicious is 1-9
- `Clean`: malicious = 0 with a known result
- `Undetected`: VirusTotal has no record for the SHA-256 hash
- `Error`: invalid input or runtime/API error

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

Reports include summary counts and per-item scan results.

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
|   `-- dialogs.py
|-- common/
|   |-- __init__.py
|   |-- cache.py
|   |-- env.py
|   |-- reporting.py
|   `-- service.py
|-- cache/
|   `-- vt_cache.db
|-- requirements-cli.txt
|-- requirements-gui.txt
`-- README.md
```
