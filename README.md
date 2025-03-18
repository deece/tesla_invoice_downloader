# Tesla Invoice Downloader

## Overview

**Tesla Invoice Downloader** is a Python script that retrieves Tesla charging invoices via the Fleet API. It authenticates via OAuth, fetches charging history, and downloads invoices as PDF files. The script can run as a one-time operation or as a daemon checking for new invoices every hour.

## License

**Copyright © 2025 Alastair D'Silva**

This project is licensed under the **GNU General Public License v3 (GPLv3)**. See the [LICENSE](LICENSE) file for details.

## Features

- OAuth authentication with Tesla Developer API
- Fetches charging history and invoices
- Supports filtering by VIN
- Only retrieves invoices since the last saved charge session
- Saves metadata alongside invoices in JSON format
- Daemon mode: checks for new invoices every hour
- Configurable output directory and logging

## Installation

### Prerequisites

- Python 3.7+
- Install dependencies:
  ```sh
  pip install requests
  ```

## Usage

Run the script with the following options:

```sh
python tesla_invoice_downloader.py [OPTIONS]
```

### Command-line Arguments

| Option             | Description |
|--------------------|-------------|
| `--vin VIN`       | Restrict invoices to a specific VIN |
| `--output-dir DIR`| Directory to save invoices (default: current directory) |
| `--log-file FILE` | File to save logs (optional) |
| `--daemon`        | Run as a background process, checking for new invoices every hour |
| `--debug`         | Enable debug logging |

### Example Usage

1. **One-time download**
   ```sh
   python tesla_invoice_downloader.py --output-dir ~/invoices
   ```

2. **Filter invoices for a specific VIN**
   ```sh
   python tesla_invoice_downloader.py --vin 5YJSA1E26JF278XXX
   ```

3. **Run in daemon mode**
   ```sh
   python tesla_invoice_downloader.py --daemon --output-dir ~/invoices --log-file ~/logs/invoice.log
   ```

## Tesla Developer Setup

Before using the script, create a Tesla Developer app:

1. Go to [Tesla Developer Portal](https://developer.tesla.com/)
2. Click **"Get Started"** and create an application with the following settings:
   - **Application Name:** (Cannot contain "Tesla")
   - **OAuth Grant Type:** Authorization Code and Machine-to-Machine
   - **Allowed Origin URL:** `http://localhost:8585`
   - **Allowed Redirect URI:** `http://localhost:8585/callback`
   - **API & Scopes:** Select "Vehicle Charging Management"
3. Save your **Client ID** and **Client Secret**.
4. Run the script and enter these credentials when prompted.

## File Naming Convention

Invoices are saved with the following filename format:

```
YYYYMMDD.Tesla.Charging - <location> - <charging_usage>kWh.<currencySymbol><total_due>.pdf
```

Where:
- `YYYYMMDD`: Charge start date
- `<location>`: Site location
- `<charging_usage>`: Total charging kWh
- `<currencySymbol>`: Currency symbol (e.g., `$` for AUD/CAD, `€` for EUR)
- `<total_due>`: Total charge cost

## Configuration File

The script stores authentication tokens and charging history in:

```
~/.tesla_invoice_downloader.json
```

This file is updated automatically and should be kept secure.

## Contributing

Pull requests and contributions are welcome! Please ensure your code adheres to the project structure and style.

## Issues & Support

If you encounter any issues, feel free to open a GitHub issue or reach out.

## Acknowledgments

- Tesla Developer API documentation
- Open-source community for Python tools

## Disclaimer

This project is not affiliated with or endorsed by Tesla, Inc.


