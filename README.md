# VirusProbe

VirusProbe is a VirusTotal-powered SHA-256 scanner with both a command-line interface and a desktop GUI.

- CLI entrypoint: `cli.py`
- GUI entrypoint: `gui.py`
- Shared engine: `common/service.py`
- Shared report writer: `common/reporting.py`

## Quick Start

1. Install dependencies:

```bash
pip install -r requirements-cli.txt
pip install -r requirements-gui.txt
```

```powershell
pip install -r requirements-cli.txt
pip install -r requirements-gui.txt
```

2. Set your VirusTotal API key:

```bash
export VT_API_KEY="your_api_key_here"
```

```powershell
$env:VT_API_KEY="your_api_key_here"
```

3. Run a first CLI scan:

```bash
python cli.py -h 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
```

```powershell
python cli.py -h 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F
```

4. Optional: generate a report:

```bash
python cli.py -h 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F -o report.json --format json
```

```powershell
python cli.py -h 275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F -o report.json --format json
```

5. Launch the GUI:

```bash
python gui.py
```

```powershell
python gui.py
```

## What It Does

VirusProbe scans:
- files
- directories (CLI)
- SHA-256 hashes

And provides:
- consistent verdict categories (`Malicious`, `Suspicious`, `Clean`, `Undetected`)
- local caching (memory + SQLite) to reduce repeat API calls
- report export in `json`, `csv`, `txt`, and `md`

## Project Structure

```text
Virus Check Tool/
|-- cli.py
|-- gui.py
|-- cli/
|   `-- app.py
|-- gui/
|   `-- app.py
|-- common/
|   |-- service.py
|   `-- reporting.py
|-- cache/
|   `-- vt_cache.db
|-- requirements-cli.txt
|-- requirements-gui.txt
`-- README.md
```

## Requirements

- Python 3.11 or newer
- A VirusTotal API key

## Installation

### CLI

```bash
pip install -r requirements-cli.txt
```

```powershell
pip install -r requirements-cli.txt
```

### GUI

```bash
pip install -r requirements-gui.txt
```

```powershell
pip install -r requirements-gui.txt
```

Notes:
- `requirements-gui.txt` includes `tkinterdnd2` for drag-and-drop support.
- Tkinter itself is part of most standard Python installs.

## Running

### CLI

```bash
python cli.py --help
```

```powershell
python cli.py --help
```

### GUI

```bash
python gui.py
```

```powershell
python gui.py
```

## API Key Configuration

VirusProbe checks API key sources in this order:
1. CLI `--api-key`
2. Environment variables: `VT_API_KEY`, `VIRUSTOTAL_API_KEY`
3. Local `.env` file in project root

Example `.env`:

```env
VT_API_KEY=your_api_key_here
```

### CLI API key commands

Save key into `.env`:

```bash
python cli.py --api-key YOUR_KEY --save-api-key
```

```powershell
python cli.py --api-key YOUR_KEY --save-api-key
```

Remove saved key from `.env`:

```bash
python cli.py --clear-api-key
```

```powershell
python cli.py --clear-api-key
```

### GUI API key behavior

- Use **Set API Key**
- Key is autosaved to `.env`
- GUI status masks the key as `xxxx...xxxx`

## CLI Usage

### Input rules

- `--file` and `--directory` cannot be used together
- `--directory` can be combined with `--hash`
- `--recursive` is valid only with `--directory`

### Common commands

Scan one or more files:

```bash
python cli.py -f file1.exe file2.dll
```

```powershell
python cli.py -f file1.exe file2.dll
```

Scan one or more hashes:

```bash
python cli.py -h HASH1 HASH2
```

```powershell
python cli.py -h HASH1 HASH2
```

Scan a directory:

```bash
python cli.py -d /path/to/folder
```

```powershell
python cli.py -d C:\path\to\folder
```

Scan directory recursively:

```bash
python cli.py -d /path/to/folder -r
```

```powershell
python cli.py -d C:\path\to\folder -r
```

Scan directory + hashes in one run:

```bash
python cli.py -d /path/to/folder -h HASH1 HASH2
```

```powershell
python cli.py -d C:\path\to\folder -h HASH1 HASH2
```

Write a report:

```bash
python cli.py -f sample.exe -o reports/scan.json --format json
```

```powershell
python cli.py -f sample.exe -o reports\scan.json --format json
```

Supported report formats:
- `json`
- `csv`
- `txt`
- `md`

### CLI options reference

- `-f, --file, --files`: one or more file paths
- `-h, --hash, --hashes`: one or more SHA-256 hashes
- `-d, --directory, --dir`: directory path
- `-r, --recursive`: recurse subdirectories (directory mode only)
- `-o, --output`: output report path
- `--format`: `json|csv|txt|md` (default `json`)
- `--api-key`: API key override
- `--save-api-key`: persist `--api-key` to `.env`
- `--clear-api-key`: remove saved key from `.env`
- `--clear-cache`: clear local cache
- `--help`: show help

## GUI Usage

GUI supports:
- Add Item menu:
  - Add File(s)
  - Add SHA-256 Hash
  - Add Multiple SHA-256 Hashes (one per line)
- drag-and-drop files directly into the list
- per-item scan status in a table
- deduping identical queued items
- Generate Report dialog (name, type, destination folder)
- report completion dialog with:
  - **Open Report**
  - **Open Folder**
- **Clear Cache** action

Report button behavior:
- visible always
- disabled until at least one scan completes

## Cache Behavior

VirusProbe uses two cache layers:

1. In-memory LRU cache (process-local)
- default max entries: `512`
- cleared when process exits
- fastest lookup path

2. SQLite cache in `cache/vt_cache.db`
- WAL mode enabled
- default row cap: `10000`
- default expiry: `7` days
- stores compact binary hash + packed stats

Expected companion files when WAL is active:
- `cache/vt_cache.db-wal`
- `cache/vt_cache.db-shm`

### Clearing cache

`--clear-cache` (CLI) and **Clear Cache** (GUI):
- clears SQLite rows
- checkpoints/truncates WAL
- clears in-memory cache for the running process

This is intentional so old in-process entries do not survive after a cache clear.

## Scoring and Verdict Criteria

Per item:
- `Malicious`: malicious detections >= 10
- `Suspicious`: malicious detections between 1 and 9
- `Clean`: malicious detections == 0 and result exists
- `Undetected`: VirusTotal has no record for the hash

Displayed engine stats:
- `malicious`
- `suspicious`
- `harmless`
- `undetected`

Final summary uses the same verdict language as per-item output.

## Reports

All report formats include:
- generation timestamp
- summary counts
- per-item results

Format notes:
- `json`: structured output with full result objects
- `csv`: flat tabular export with key fields
- `txt`: human-readable summary and line entries
- `md`: Markdown table format

## Error Handling Notes

- Missing file paths in CLI `--file` list are skipped and reported, not scanned.
- Invalid/nonexistent directory for `--directory` raises an input error.
- Hashes with no VT record are treated as `Undetected` (not a crash).
- Unexpected VT/API/cache errors are returned as per-item `status=error`.

## Security Notes

- Do not hardcode API keys in source files.
- Prefer `.env` or environment variables.
- `.env` should be treated as sensitive and excluded from source control.

## Troubleshooting

`VirusTotal API key is required`:
- set `VT_API_KEY` or pass `--api-key`

Drag-and-drop does not work in GUI:
- ensure GUI dependencies are installed:
  - Bash: `pip install -r requirements-gui.txt`
  - PowerShell: `pip install -r requirements-gui.txt`
- verify `tkinterdnd2` is installed in the same Python environment as `gui.py`
- on Linux, ensure a Tcl/Tk installation is present (`sudo apt install python3-tk`)

Seeing `vt_cache.db-wal` and `vt_cache.db-shm`:
- normal SQLite WAL behavior

Cache clear did not reduce RAM in another running app:
- in-memory cache is per process; clear in each running process or restart apps
