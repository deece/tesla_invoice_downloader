#!/usr/bin/env python3
"""
Tesla Invoice Downloader Script (GPLv3)
========================================

Copyright © 2025 Alastair D'Silva

This script is licensed under the GNU General Public License version 3 (GPLv3).

Description:
------------
This script uses the Tesla Fleet API to authenticate via OAuth, retrieve charging history,
and download charging invoices (PDF) along with their metadata.
It stores configuration (including API tokens and charging history) in ~/.tesla_invoice_downloader.json.
It supports filtering by VIN and only fetching history since the last recorded chargeStartDateTime for that VIN.
Invoices are saved with a filename in the form:

    YYYYMMDD.Tesla.Charging - <location> - <charging_usage>kWh.<currencySymbol><total_due>.pdf

where:
    - YYYYMMDD is derived from the chargeStartDateTime (with a 4-digit year),
    - <location> is the site's location,
    - <charging_usage> is the sum of usageBase for fees with feeType "CHARGING" (2 decimals),
    - <total_due> is the sum of totalDue for all fees (2 decimals),
    - The currency symbol is determined from the currencyCode of the first fee (for AUD and CAD, it is "$").

When daemonised, the script will check for new invoices once per hour.

Usage:
------
    python tesla_invoice_downloader.py [--vin VIN] [--output-dir OUTPUT_DIR] [--log-file LOG_FILE] [--daemon] [--debug]

    (C) 2025 Alastair D'Silva

Onboarding Instructions:
------------------------
Before using this script, create your Tesla Developer app by visiting:
    https://developer.tesla.com/
and clicking **"Get Started"**.

Fill in the details as follows:
  - **Application Details:**
      - Application Name: (choose a name that does not contain "Tesla")
      - Application Description & Purpose of Usage: (briefly describe your app's functionality)
  - **Client Details:**
      - OAuth Grant Type: Select "Authorization Code and Machine-to-Machine"
      - Allowed Origin URL: Set to "http://localhost:8585"
      - Allowed Redirect URI: Set to "http://localhost:8585/callback"
  - **API & Scopes:**
      - Select "Vehicle Charging Management" (this gives access to charging history and invoices)
  - **Billing Details:**
      - These can be skipped if not applicable.

After creating your app, use your **Client ID** and **Client Secret** when prompted by this script.

Dependencies:
-------------
    pip install requests
"""

import os
import sys
import json
import logging
import socket
import webbrowser
from urllib.parse import urlparse, parse_qs
import time
import secrets
import requests
import argparse
import datetime
import re

# Global configuration
CONFIG_PATH = os.path.expanduser("~/.tesla_invoice_downloader.json")
BACKUP_FORMAT = "%Y%m%d.%H%M%S"  # Timestamp format for backup files
DEFAULT_REDIRECT_URI = "http://localhost:8585/callback"

# Create a global logger instance
logger = logging.getLogger("tesla_invoice_downloader")
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter("%(levelname)s: %(message)s")
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

def daemonize():
    """Daemonize the process using the double-fork method (Unix only)."""
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        logger.error(f"First fork failed: {e}")
        sys.exit(1)
    os.chdir("/")
    os.setsid()
    os.umask(0)
    try:
        if os.fork() > 0:
            sys.exit(0)
    except OSError as e:
        logger.error(f"Second fork failed: {e}")
        sys.exit(1)
    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null', 'r') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'a+') as dev_null:
        os.dup2(dev_null.fileno(), sys.stdout.fileno())
        os.dup2(dev_null.fileno(), sys.stderr.fileno())

def safe_filename(s):
    """
    Remove known bad characters from the filename.
    Removes: \ / : * ? " < > |
    """
    return re.sub(r'[\\\/:*?"<>|]', '', s)

def redact_sensitive(data):
    """
    Redact sensitive keys from dictionaries or strings.
    For dictionaries, keys such as 'Authorization', 'client_secret', 'access_token', and 'refresh_token'
    are replaced with asterisks.
    For strings, if "Bearer " is found, it is replaced.
    """
    if isinstance(data, dict):
        redacted = {}
        for key, value in data.items():
            if key.lower() in ("authorization", "client_secret", "access_token", "refresh_token"):
                redacted[key] = "***"
            else:
                redacted[key] = value
        return redacted
    elif isinstance(data, str):
        return data.replace("Bearer ", "Bearer ***")
    else:
        return data

def load_config():
    """Load configuration from the JSON file, or return an empty dict if not present."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                data = json.load(f)
                logger.debug(f"Loaded config: {data}")
                return data
        except Exception as e:
            logger.error(f"Failed to read config file: {e}")
            return {}
    else:
        return {}

def save_config(data):
    """Save configuration to the JSON file, with a backup of the previous file."""
    if os.path.exists(CONFIG_PATH):
        timestamp = time.strftime(BACKUP_FORMAT, time.localtime())
        backup_path = f"{CONFIG_PATH}.{timestamp}"
        try:
            os.rename(CONFIG_PATH, backup_path)
            logger.info(f"Backup of old config created: {backup_path}")
        except Exception as e:
            logger.warning(f"Could not create backup of config: {e}")
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(data, f, indent=4)
        os.chmod(CONFIG_PATH, 0o600)
        logger.info(f"Configuration saved to {CONFIG_PATH}")
    except Exception as e:
        logger.error(f"Failed to save config: {e}")

def get_base_url_for_region(region):
    """Return the Fleet API base URL for the given region code."""
    region = region.upper()
    if region == "EU":
        return "https://fleet-api.prd.eu.vn.cloud.tesla.com"
    else:
        return "https://fleet-api.prd.na.vn.cloud.tesla.com"

def exchange_code_for_token(auth_code, client_id, client_secret, redirect_uri, region):
    """Exchange the authorization code for access and refresh tokens."""
    token_url = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
    audience = get_base_url_for_region(region)
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "audience": audience
    }
    logger.debug(f"Exchanging token: URL: {token_url} Data: {redact_sensitive(data)}")
    response = requests.post(token_url, data=data)
    logger.debug(f"Response status: {response.status_code} Data: {response.text}")
    try:
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Token exchange failed: {response.text}")
        raise
    token_data = response.json()
    logger.debug(f"Token response JSON: {redact_sensitive(token_data)}")
    return token_data

def refresh_access_token(refresh_token, client_id, region):
    """Use a refresh token to get a new access token (and new refresh token)."""
    token_url = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
    data = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token
    }
    logger.debug(f"Refreshing token: URL: {token_url} Data: {redact_sensitive(data)}")
    response = requests.post(token_url, data=data)
    logger.debug(f"Response status: {response.status_code} Data: {response.text}")
    try:
        response.raise_for_status()
    except Exception as e:
        logger.error(f"Token refresh failed: {response.text}")
        raise
    token_data = response.json()
    logger.debug(f"Refresh token response JSON: {redact_sensitive(token_data)}")
    return token_data

def authenticate_and_get_tokens(config):
    """
    Return an access token from the config if available.
    Only attempt to refresh (or prompt for new credentials) if no access token is stored.
    """
    if config.get("access_token"):
        logger.info("Using existing access token from config.")
        return config["access_token"]

    if config.get("refresh_token"):
        try:
            new_tokens = refresh_access_token(config["refresh_token"], config["client_id"], config.get("region", "NA"))
            config["access_token"] = new_tokens.get("access_token")
            if new_tokens.get("refresh_token"):
                config["refresh_token"] = new_tokens.get("refresh_token")
            logger.info("Access token refreshed successfully.")
            save_config(config)
            return config["access_token"]
        except Exception:
            logger.warning("Refresh token failed or expired. A new login is required.")

    print("Enter your Tesla API Client ID and Client Secret.")
    client_id = input("Client ID: ").strip()
    client_secret = input("Client Secret: ").strip()
    config["client_id"] = client_id
    config["client_secret"] = client_secret
    config["redirect_uri"] = DEFAULT_REDIRECT_URI
    if "region" not in config:
        region = input("Account region (NA/EU, default NA): ").strip() or "NA"
        config["region"] = region.upper()
    save_config(config)

    state = secrets.token_urlsafe(16)
    scope = "openid offline_access vehicle_charging_cmds"
    auth_url = (
        f"https://auth.tesla.com/oauth2/v3/authorize?"
        f"response_type=code&client_id={client_id}&redirect_uri={DEFAULT_REDIRECT_URI}"
        f"&scope={scope}&state={state}&prompt=login"
    )
    logger.info("Opening Tesla authorization page in your browser...")
    logger.debug(f"Auth URL: {auth_url}")

    parsed = urlparse(DEFAULT_REDIRECT_URI)
    host = parsed.hostname or "localhost"
    port = parsed.port or 80
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.bind((host, port))
        server_sock.listen(1)
    except Exception as e:
        logger.error(f"Failed to start local server on {host}:{port}: {e}")
        logger.info("If the browser cannot redirect to the local server, please copy the URL manually.")
        exit(1)

    webbrowser.open(auth_url)
    logger.info("Waiting for OAuth callback with authorization code over HTTP...")

    server_sock.settimeout(300)
    try:
        conn, addr = server_sock.accept()
    except socket.timeout:
        logger.error("OAuth authorization timed out. No response received.")
        server_sock.close()
        redirect_resp = input("Login timed out.\nIf you did log in, please paste the URL you were redirected to: ")
        try:
            parsed_url = urlparse(redirect_resp.strip())
            query_params = parse_qs(parsed_url.query)
            auth_code = query_params.get("code")[0] if query_params.get("code") else None
            returned_state = query_params.get("state")[0] if query_params.get("state") else None
        except Exception:
            logger.error("Failed to parse the provided URL. Please try again.")
            return None
    else:
        request_data = conn.recv(1024).decode('utf-8', errors='ignore')
        request_line = request_data.splitlines()[0]
        if "GET" in request_line:
            path = request_line.split(" ", 2)[1]
        else:
            path = ""
        parsed_url = urlparse(path)
        query_params = parse_qs(parsed_url.query)
        auth_code = query_params.get("code")[0] if query_params.get("code") else None
        returned_state = query_params.get("state")[0] if query_params.get("state") else None
        http_response = ("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                         "<html><body><h1>Authentication complete.</h1>"
                         "<p>You can close this window and return to the application.</p></body></html>")
        conn.send(http_response.encode('utf-8'))
        conn.close()
        server_sock.close()

    if returned_state != state:
        logger.error("State mismatch! Potential CSRF attack or incorrect redirect.")
        return None
    if not auth_code:
        logger.error("Authorization code not found in redirect. Login may have failed.")
        return None

    logger.info("Authorization code received. Exchanging for tokens...")
    token_data = exchange_code_for_token(auth_code, client_id, client_secret, DEFAULT_REDIRECT_URI, config.get("region", "NA"))
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not access_token or not refresh_token:
        logger.error("Failed to obtain access or refresh token from Tesla.")
        return None
    config["access_token"] = access_token
    config["refresh_token"] = refresh_token
    save_config(config)
    logger.info("OAuth authentication succeeded. Access token and refresh token obtained.")
    return access_token

def fetch_charging_history(base_url, access_token, vin=None):
    """
    Fetch charging history records from the Fleet API using a page size of 50.
    If a VIN is provided, add the 'vin' parameter and, if charging history for that VIN
    exists in config, add the 'startTime' parameter set to the most recent chargeStartDateTime.
    After retrieval, store the history in config grouped by VIN (sorted ascending by chargeStartDateTime).
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    all_records = []
    page = 1
    page_size = 50
    params = {"pageSize": page_size}
    if vin:
        params["vin"] = vin
        config = load_config()
        stored = config.get("charging_history", {}).get(vin, [])
        if stored:
            last_time = stored[-1].get("chargeStartDateTime")
            if last_time:
                params["startTime"] = last_time
                logger.info(f"Using startTime={last_time} for VIN {vin} based on stored history.")
    logger.info("Retrieving charging history...")
    while True:
        params["pageNo"] = page
        url = f"{base_url}/api/1/dx/charging/history"
        logger.debug(f"Fetching charging history: URL: {url} Headers: {redact_sensitive(headers)} Params: {params}")
        try:
            resp = requests.get(url, headers=headers, params=params)
        except Exception as e:
            logger.error(f"Network error fetching charging history (page {page}): {e}")
            break
        logger.debug(f"Response status: {resp.status_code} Data: {resp.text}")
        if resp.status_code == 401:
            logger.warning("Access token expired during history fetch. Trying to refresh and retry...")
            return None
        if resp.status_code != 200:
            logger.error(f"Error fetching charging history (HTTP {resp.status_code}): {resp.text}")
            break
        data = resp.json()
        if isinstance(data, list):
            records = data
        elif "data" in data:
            records = data["data"]
        elif "results" in data:
            records = data["results"]
        elif "response" in data:
            records = data["response"]
        elif "chargingHistory" in data:
            records = data["chargingHistory"]
        else:
            records = data.get("records") or data.get("history") or []
        if not records:
            break
        all_records.extend(records)
        logger.info(f"Fetched {len(records)} records from page {page}.")
        if len(records) < page_size:
            break
        page += 1
    logger.info(f"Total charging sessions retrieved: {len(all_records)}")
    config = load_config()
    if "charging_history" not in config:
        config["charging_history"] = {}
    if vin:
        existing = config["charging_history"].get(vin, [])
        merged = { rec.get("sessionId"): rec for rec in existing }
        for rec in all_records:
            merged[rec.get("sessionId")] = rec
        merged_list = list(merged.values())
        merged_list.sort(key=lambda r: r.get("chargeStartDateTime", ""))
        config["charging_history"][vin] = merged_list
    else:
        grouped = config["charging_history"]
        for rec in all_records:
            rec_vin = rec.get("vin", "Unknown")
            if rec_vin not in grouped:
                grouped[rec_vin] = []
            if not any(r.get("sessionId") == rec.get("sessionId") for r in grouped[rec_vin]):
                grouped[rec_vin].append(rec)
            grouped[rec_vin].sort(key=lambda r: r.get("chargeStartDateTime", ""))
        config["charging_history"] = grouped
    save_config(config)
    return all_records

def download_invoices(records, vin_filter=None, output_dir="."):
    """
    Download PDF invoices for each record that has an invoice, and save metadata JSON.

    The output filename is in the form:

    YYYYMMDD.Tesla.Charging - <location> - <charging_usage>kWh.<currencySymbol><total_due>.pdf

    where:
      - YYYYMMDD is derived from chargeStartDateTime,
      - <location> is the site's location,
      - <charging_usage> is the sum of usageBase for CHARGING fees (2 decimals),
      - <total_due> is the sum of totalDue for all fees (2 decimals),
      - The currency symbol is determined from the currencyCode of the first fee using a local dictionary.

    If vin_filter is provided, only process records with that VIN.
    Files are saved to the specified output directory.
    """
    if not records:
        logger.info("No charging records to process for invoices.")
        return

    CURRENCY_SYMBOLS = {
        "AUD": "$",
        "USD": "$",
        "CAD": "$",
        "EUR": "€",
        "GBP": "£",
        "JPY": "¥",
        "CNY": "¥"
    }

    for rec in records:
        if vin_filter and rec.get("vin") != vin_filter:
            continue
        invoices_info = rec.get("invoices") or rec.get("Invoices")
        if not invoices_info:
            continue
        inv = invoices_info[0]
        inv_id = inv.get("contentId") or inv.get("id")
        if not inv_id:
            logger.warning("No invoice ID found for a record, skipping.")
            continue
        charge_start = rec.get("chargeStartDateTime")
        if charge_start:
            try:
                dt = datetime.datetime.fromisoformat(charge_start)
                date_str = dt.strftime("%Y%m%d")
            except Exception:
                date_str = "00000000"
        else:
            date_str = "00000000"
        location = rec.get("siteLocationName", "Unknown")
        charging_usage = 0.0
        total_due = 0.0
        fees = rec.get("fees", [])
        for fee in fees:
            try:
                if fee.get("feeType") == "CHARGING" and fee.get("usageBase") is not None:
                    charging_usage += float(fee.get("usageBase"))
            except Exception:
                pass
            try:
                if fee.get("totalDue") is not None:
                    total_due += float(fee.get("totalDue"))
            except Exception:
                pass
        currency_symbol = ""
        if fees:
            currency_code = fees[0].get("currencyCode", "")
            currency_symbol = CURRENCY_SYMBOLS.get(currency_code, "")
        file_name = f"{date_str}.Tesla.Charging - {location} - {charging_usage:.2f}kWh.{currency_symbol}{total_due:.2f}.pdf"
        file_name = safe_filename(file_name)
        file_path = os.path.join(output_dir, file_name)
        if os.path.exists(file_path):
            logger.info(f"Invoice {file_path} already exists. Skipping download.")
            continue
        config = load_config()
        base_url = get_base_url_for_region(config.get("region", "NA"))
        invoice_url = f"{base_url}/api/1/dx/charging/invoice/{inv_id}"
        logger.info(f"Downloading invoice PDF: {file_path}")
        logger.debug(f"Invoice URL: {invoice_url}")
        try:
            resp = requests.get(invoice_url, headers={"Authorization": f"Bearer {config.get('access_token')}"})
        except Exception as e:
            logger.error(f"Network error downloading invoice {file_path}: {e}")
            continue
        logger.debug(f"Response status: {resp.status_code} Data: {resp.text[:200]}")
        if resp.status_code != 200:
            logger.error(f"Failed to download invoice {inv_id} (HTTP {resp.status_code}): {resp.text}")
            continue
        try:
            with open(file_path, 'wb') as pdf_file:
                pdf_file.write(resp.content)
            logger.info(f"Saved invoice PDF: {file_path}")
        except Exception as e:
            logger.error(f"Error saving PDF file {file_path}: {e}")
            continue
        meta_name = os.path.splitext(file_path)[0] + ".json"
        try:
            with open(meta_name, 'w') as meta_file:
                json.dump(rec, meta_file, indent=4)
            logger.info(f"Saved invoice metadata: {meta_name}")
        except Exception as e:
            logger.error(f"Error saving metadata file {meta_name}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tesla Invoice Downloader with HTTP Callback, Logging, and Daemonisation")
    parser.add_argument("--vin", help="Restrict to a particular VIN", default=None)
    parser.add_argument("--output-dir", help="Directory to save invoice files", default=".")
    parser.add_argument("--log-file", help="File to write logs to", default=None)
    parser.add_argument("--daemon", action="store_true", help="Daemonise the process to run in the background")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    # Configure logging to file if specified.
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        logger.info(f"Logging to file: {args.log_file}")

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled.")

    if args.daemon:
        logger.info("Daemonising process...")
        daemonize()
        # Run indefinitely, checking for new invoices once per hour.
        while True:
            config = load_config()
            access_token = authenticate_and_get_tokens(config)
            if not access_token:
                logger.error("Authentication failed. Exiting daemon.")
                sys.exit(1)
            base_url = get_base_url_for_region(config.get("region", "NA"))
            records = fetch_charging_history(base_url, access_token, vin=args.vin)
            if records is None:
                config = load_config()
                new_token = None
                if config.get("refresh_token"):
                    try:
                        tokens = refresh_access_token(config["refresh_token"], config["client_id"], config.get("region", "NA"))
                        config["access_token"] = tokens.get("access_token")
                        if tokens.get("refresh_token"):
                            config["refresh_token"] = tokens.get("refresh_token")
                        save_config(config)
                        new_token = config["access_token"]
                        logger.info("Retried with refreshed token...")
                    except Exception as e:
                        logger.error("Retried token refresh failed. Exiting daemon.")
                        sys.exit(1)
                if not new_token:
                    new_token = authenticate_and_get_tokens(config)
                if not new_token:
                    logger.error("Could not authenticate to fetch charging history. Exiting daemon.")
                    sys.exit(1)
                records = fetch_charging_history(base_url, new_token, vin=args.vin)
            download_invoices(records, vin_filter=args.vin, output_dir=args.output_dir)
            logger.info("Cycle complete. Sleeping for one hour...")
            time.sleep(3600)
    else:
        config = load_config()
        access_token = authenticate_and_get_tokens(config)
        if not access_token:
            logger.error("Authentication failed. Exiting.")
            sys.exit(1)
        base_url = get_base_url_for_region(config.get("region", "NA"))
        records = fetch_charging_history(base_url, access_token, vin=args.vin)
        if records is None:
            config = load_config()
            new_token = None
            if config.get("refresh_token"):
                try:
                    tokens = refresh_access_token(config["refresh_token"], config["client_id"], config.get("region", "NA"))
                    config["access_token"] = tokens.get("access_token")
                    if tokens.get("refresh_token"):
                        config["refresh_token"] = tokens.get("refresh_token")
                    save_config(config)
                    new_token = config["access_token"]
                    logger.info("Retried with refreshed token...")
                except Exception as e:
                    logger.error("Retried token refresh failed. Exiting.")
                    sys.exit(1)
            if not new_token:
                new_token = authenticate_and_get_tokens(config)
            if not new_token:
                logger.error("Could not authenticate to fetch charging history. Exiting.")
                sys.exit(1)
            records = fetch_charging_history(base_url, new_token, vin=args.vin)
        download_invoices(records, vin_filter=args.vin, output_dir=args.output_dir)
        logger.info("Done. All available invoices have been downloaded.")
