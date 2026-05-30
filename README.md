# PERE — PE Risk Engine

PERE is a lightweight Windows-focused static analysis engine for Portable Executable (PE) files. It inspects imported APIs, examines digital signature metadata, and computes a heuristic risk score to help triage suspicious binaries.

## Features

- Static PE analysis for `.exe` and `.dll` files
- Import-based behavioral scoring
- Signature trust evaluation (`unsigned`, `selfsigned`, `valid`)
- Detection of injection chains and stealth process injection patterns
- Timestamp collection and anomaly scoring (`--timestamps`)
- JSON report export
- Colorized terminal output via `colorama`

## Important Disclaimer

This tool is not a replacement for endpoint detection and response (EDR) systems. It is a lightweight, rapid triage utility for inspecting PE files (for example binaries that may have been dropped or modified after a compromise). Use it as a first-pass aid during investigations — follow up with full EDR, dynamic analysis, and forensic procedures for definitive conclusions.

## Requirements

- Python 3.11+ recommended
- Windows environment for meaningful PE analysis

## Installation

1. Clone or download the repository.
2. Create a virtual environment (recommended):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

## Usage

Run the main analyzer with the target directory path:

```powershell
python main.py --path C:\path\to\binaries
```

Optional arguments:

- `--extensions`: comma-separated extensions to scan (default: `exe,dll`)
- `--timestamps`: include file and PE timestamp details, and score anomalous dates
- `--json`: save results to a JSON report
- `--output`: JSON output filename (default: `report.json`)

Example:

```powershell
python main.py --path C:\samples --extensions exe,dll --json --output findings.json
```

## Demo
<video src="https://github.com/n00bDebugger-git/PERE/blob/main/assets/demo.webm" controls></video>


## How It Works

- `main.py` scans the provided directory and invokes `analyzer.analyze_file()` for each matching file.
- `analyzer.py` loads the PE file using `pefile`, extracts imported functions, inspects Authenticode signature metadata, and optionally gathers timestamp metadata.
- `rules.py` scores detected APIs, signature data, and timestamp anomalies when `--timestamps` is enabled, generating findings and a combined risk score.
- `engine.py` currently forwards the evaluation result from `rules.py` and can be extended for future scoring enhancements.

## Risk Scoring

PERE uses grouped API scoring and heuristic detections such as:

- Memory APIs (e.g. `VirtualAlloc`, `WriteProcessMemory`)
- Injection APIs (e.g. `CreateRemoteThread`, `OpenProcess`)
- Execution APIs (e.g. `CreateProcessA`, `ShellExecuteW`)
- Dynamic loading APIs (`LoadLibrary`, `GetProcAddress`)
- Persistence APIs (`RegSetValueEx`, `RegCreateKeyEx`)

Special pattern detections include:

- `Injection Chain`
- `Stealth Injection`
- `Dynamic API Resolution`

Trusted signed binaries from selected publishers can bypass scoring.

## Project Structure

- `main.py` — CLI entrypoint and output formatting
- `scanner.py` — directory traversal and extension filtering
- `analyzer.py` — PE parsing, import extraction, and signature detection
- `rules.py` — scoring rules and risk evaluation
- `engine.py` — evaluation orchestration
- `requirements.txt` — package dependencies

## License

See `LICENSE` for license details.
