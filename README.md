# Windows Activity Tracker

A Python script that tracks user activity from Windows Security Event Log and exports to Excel.

## Quick Start

```bash
# Install dependencies
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run with default user (JohnDoe)
python activity_tracker.py

# Specify different user
python activity_tracker.py "Jane Smith"
python activity_tracker.py -u "Jane Smith"
```

## Requirements

- Windows with Security Event Log access
- Administrator privileges
- Python 3.6+

## Output

Creates `activity_log.xlsx` with:
- **Professional formatting** with color-coded headers
- **Time columns** for each date (Start, End, Duration)
- **Frozen panes** - first column stays visible when scrolling
- **Automatic formulas** for duration calculations
- **Incremental updates** - only changes when needed

## Features

✅ Tracks lock/unlock events to calculate active sessions
✅ Minimum 5-minute session filtering
✅ Alternating row colors for readability
✅ Command line argument support
✅ Professional Excel formatting

## Usage Examples

```bash
python activity_tracker.py                   # Default user
python activity_tracker.py JDoe              # Specific user
python activity_tracker.py -u "John Doe"     # With flag
python activity_tracker.py -h                # Help
```

## Note

Requires administrator privileges to read Security Event Log. Make sure Excel file is closed before running.
