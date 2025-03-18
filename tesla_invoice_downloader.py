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
from typing import Any, Dict, List, Optional, Union

# Global configuration variables
CONFIG_PATH: str = os.path.expanduser("~/.tesla_invoice_downloader.json")
BACKUP_FORMAT: str = "%Y%m%d.%H%M%S"
DEFAULT_REDIRECT_URI: str = "http://localhost:8585/callback"

# Global logger
logger: logging.Logger = logging.getLogger("tesla_invoice_downloader")
logger.setLevel(logging.INFO)
consoleHandler: logging.StreamHandler = logging.StreamHandler()
consoleFormatter: logging.Formatter = logging.Formatter("%(levelname)s: %(message)s")
consoleHandler.setFormatter(consoleFormatter)
logger.addHandler(consoleHandler)

def daemonize() -> None:
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

def safeFilename(s: str) -> str:
    """Remove known bad characters from the filename."""
    return re.sub(r'[\\\/:*?"<>|]', '', s)

def redactSensitive(data: Union[Dict[str, Any], str]) -> Union[Dict[str, Any], str]:
    """Redact sensitive keys from dictionaries or strings."""
    if isinstance(data, dict):
        return {k: ("***" if k.lower() in ("authorization", "client_secret", "access_token", "refresh_token") else v)
                for k, v in data.items()}
    elif isinstance(data, str):
        return data.replace("Bearer ", "Bearer ***")
    else:
        return data

def loadConfig() -> Dict[str, Any]:
    """Load configuration from the JSON file."""
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                data: Dict[str, Any] = json.load(f)
                logger.debug(f"Loaded config: {data}")
                return data
        except Exception as e:
            logger.error(f"Failed to read config file: {e}")
            return {}
    else:
        return {}

def saveConfig(data: Dict[str, Any]) -> None:
    """Save configuration to the JSON file, with a backup."""
    if os.path.exists(CONFIG_PATH):
        timestamp: str = time.strftime(BACKUP_FORMAT, time.localtime())
        backupPath: str = f"{CONFIG_PATH}.{timestamp}"
        try:
            os.rename(CONFIG_PATH, backupPath)
            logger.info(f"Backup of old config created: {backupPath}")
        except Exception as e:
            logger.warning(f"Could not create backup of config: {e}")
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(data, f, indent=4)
        os.chmod(CONFIG_PATH, 0o600)
        logger.info(f"Configuration saved to {CONFIG_PATH}")
    except Exception as e:
        logger.error(f"Failed to save config: {e}")

def getBaseUrlForRegion(region: str) -> str:
    """Return the Fleet API base URL for the given region."""
    return "https://fleet-api.prd.eu.vn.cloud.tesla.com" if region.upper() == "EU" else "https://fleet-api.prd.na.vn.cloud.tesla.com"

def exchangeCodeForToken(authCode: str, clientId: str, clientSecret: str, redirectUri: str, region: str) -> Dict[str, Any]:
    """Exchange the authorization code for tokens."""
    tokenUrl: str = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
    audience: str = getBaseUrlForRegion(region)
    data: Dict[str, Any] = {
        "grant_type": "authorization_code",
        "client_id": clientId,
        "client_secret": clientSecret,
        "code": authCode,
        "redirect_uri": redirectUri,
        "audience": audience
    }
    logger.debug(f"Exchanging token: URL: {tokenUrl} Data: {redactSensitive(data)}")
    response: requests.Response = requests.post(tokenUrl, data=data)
    logger.debug(f"Response status: {response.status_code} Data: {response.text}")
    response.raise_for_status()
    tokenData: Dict[str, Any] = response.json()
    logger.debug(f"Token response JSON: {redactSensitive(tokenData)}")
    return tokenData

def refreshAccessToken(refreshToken: str, clientId: str, region: str) -> Dict[str, Any]:
    """Refresh the access token using a refresh token."""
    tokenUrl: str = "https://fleet-auth.prd.vn.cloud.tesla.com/oauth2/v3/token"
    data: Dict[str, Any] = {
        "grant_type": "refresh_token",
        "client_id": clientId,
        "refresh_token": refreshToken
    }
    logger.debug(f"Refreshing token: URL: {tokenUrl} Data: {redactSensitive(data)}")
    response: requests.Response = requests.post(tokenUrl, data=data)
    logger.debug(f"Response status: {response.status_code} Data: {response.text}")
    response.raise_for_status()
    tokenData: Dict[str, Any] = response.json()
    logger.debug(f"Refresh token response JSON: {redactSensitive(tokenData)}")
    return tokenData

def makeRequest(method: str, url: str, headers: Dict[str, str],
                params: Optional[Dict[str, Any]] = None,
                data: Optional[Dict[str, Any]] = None,
                retries: int = 3, backoffFactor: float = 1.0) -> requests.Response:
    """
    Make HTTP requests with exponential backoff in case of rate limiting (HTTP 429).
    """
    for attempt in range(1, retries + 1):
        try:
            if method.upper() == "GET":
                resp = requests.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                resp = requests.post(url, headers=headers, data=data)
            else:
                raise ValueError("Unsupported HTTP method")
        except Exception as e:
            logger.error(f"Network error on attempt {attempt}: {e}")
            time.sleep(backoffFactor * attempt)
            continue

        if resp.status_code == 429:
            waitTime = backoffFactor * (2 ** (attempt - 1))
            logger.warning(f"Rate limit hit (HTTP 429), waiting {waitTime:.1f} seconds...")
            time.sleep(waitTime)
            continue
        return resp
    raise Exception(f"Failed to make request to {url} after {retries} attempts.")

class TeslaInvoiceDownloader:
    def __init__(self, interactive: bool = True) -> None:
        self.config: Dict[str, Any] = loadConfig()
        self.interactive: bool = interactive

    def ensureCredentials(self) -> None:
        """Ensure required credentials are present."""
        if not self.config.get("client_id") or not self.config.get("client_secret"):
            if self.interactive:
                print("Enter your Tesla API Client ID and Client Secret.")
                self.config["client_id"] = input("Client ID: ").strip()
                self.config["client_secret"] = input("Client Secret: ").strip()
            else:
                logger.error("Missing credentials in config; cannot run in non-interactive mode.")
                sys.exit(1)
        if "region" not in self.config:
            if self.interactive:
                region = input("Account region (NA/EU, default NA): ").strip() or "NA"
                self.config["region"] = region.upper()
            else:
                self.config["region"] = "NA"
        self.config["redirect_uri"] = DEFAULT_REDIRECT_URI
        saveConfig(self.config)

    def authenticate(self) -> str:
        """
        Return a valid access token.
        Use existing token if available; otherwise, try to refresh or perform full OAuth.
        """
        if self.config.get("access_token"):
            logger.info("Using existing access token from config.")
            return self.config["access_token"]

        if self.config.get("refresh_token"):
            try:
                newTokens = refreshAccessToken(self.config["refresh_token"], self.config["client_id"], self.config.get("region", "NA"))
                self.config["access_token"] = newTokens.get("access_token")
                if newTokens.get("refresh_token"):
                    self.config["refresh_token"] = newTokens.get("refresh_token")
                logger.info("Access token refreshed successfully.")
                saveConfig(self.config)
                return self.config["access_token"]
            except Exception:
                logger.warning("Refresh token failed or expired. A new login is required.")

        if not self.interactive:
            logger.error("No valid access token and non-interactive mode; exiting.")
            sys.exit(1)

        return self.performOAuthFlow()

    def performOAuthFlow(self) -> str:
        """Perform full OAuth flow to obtain tokens."""
        self.ensureCredentials()
        clientId: str = self.config["client_id"]
        clientSecret: str = self.config["client_secret"]
        region: str = self.config.get("region", "NA")
        state: str = secrets.token_urlsafe(16)
        scope: str = "openid offline_access vehicle_charging_cmds"
        authUrl: str = (
            f"https://auth.tesla.com/oauth2/v3/authorize?"
            f"response_type=code&client_id={clientId}&redirect_uri={DEFAULT_REDIRECT_URI}"
            f"&scope={scope}&state={state}&prompt=login"
        )
        logger.info("Opening Tesla authorization page in your browser...")
        logger.debug(f"Auth URL: {authUrl}")
        parsed = urlparse(DEFAULT_REDIRECT_URI)
        host: str = parsed.hostname or "localhost"
        port: int = parsed.port or 80
        serverSock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            serverSock.bind((host, port))
            serverSock.listen(1)
        except Exception as e:
            logger.error(f"Failed to start local server on {host}:{port}: {e}")
            sys.exit(1)
        webbrowser.open(authUrl)
        logger.info("Waiting for OAuth callback with authorization code over HTTP...")
        serverSock.settimeout(300)
        try:
            conn, addr = serverSock.accept()
        except socket.timeout:
            logger.error("OAuth authorization timed out. Exiting.")
            sys.exit(1)
        requestData: str = conn.recv(1024).decode('utf-8', errors='ignore')
        requestLine: str = requestData.splitlines()[0]
        path: str = requestLine.split(" ", 2)[1] if "GET" in requestLine else ""
        parsedUrl = urlparse(path)
        queryParams: Dict[str, List[str]] = parse_qs(parsedUrl.query)
        authCode: Optional[str] = queryParams.get("code", [None])[0]
        returnedState: Optional[str] = queryParams.get("state", [None])[0]
        httpResponse: str = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
            "<html><body><h1>Authentication complete.</h1>"
            "<p>You can close this window and return to the application.</p></body></html>"
        )
        conn.send(httpResponse.encode('utf-8'))
        conn.close()
        serverSock.close()
        if returnedState != state or not authCode:
            logger.error("OAuth flow failed due to state mismatch or missing code.")
            sys.exit(1)
        logger.info("Authorization code received. Exchanging for tokens...")
        tokenData: Dict[str, Any] = exchangeCodeForToken(authCode, clientId, clientSecret, DEFAULT_REDIRECT_URI, region)
        accessToken: Optional[str] = tokenData.get("access_token")
        refreshToken: Optional[str] = tokenData.get("refresh_token")
        if not accessToken or not refreshToken:
            logger.error("Failed to obtain tokens from Tesla.")
            sys.exit(1)
        self.config["access_token"] = accessToken
        self.config["refresh_token"] = refreshToken
        saveConfig(self.config)
        logger.info("OAuth authentication succeeded.")
        return accessToken

    def parseChargingHistoryResponse(self, resp: requests.Response) -> List[Dict[str, Any]]:
        """Parse the charging history response and return a list of records."""
        data = resp.json()
        if isinstance(data, list):
            return data
        elif "data" in data:
            return data["data"]
        elif "results" in data:
            return data["results"]
        elif "response" in data:
            return data["response"]
        elif "chargingHistory" in data:
            return data["chargingHistory"]
        else:
            return data.get("records") or data.get("history") or []

    def saveHistory(self, vin: Optional[str], records: List[Dict[str, Any]]) -> None:
        """Merge new history records with stored history and save."""
        config = loadConfig()
        if "charging_history" not in config:
            config["charging_history"] = {}
        if vin:
            existing = config["charging_history"].get(vin, [])
            merged = {rec.get("sessionId"): rec for rec in existing}
            for rec in records:
                merged[rec.get("sessionId")] = rec
            mergedList = list(merged.values())
            mergedList.sort(key=lambda r: r.get("chargeStartDateTime", ""))
            config["charging_history"][vin] = mergedList
        else:
            grouped = config["charging_history"]
            for rec in records:
                recVin = rec.get("vin", "Unknown")
                if recVin not in grouped:
                    grouped[recVin] = []
                if not any(r.get("sessionId") == rec.get("sessionId") for r in grouped[recVin]):
                    grouped[recVin].append(rec)
                grouped[recVin].sort(key=lambda r: r.get("chargeStartDateTime", ""))
            config["charging_history"] = grouped
        saveConfig(config)

    def fetchChargingHistory(self, baseUrl: str, accessToken: str, vin: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch charging history records using a page size of 50.
        If vin is provided, include the 'vin' parameter and set 'startTime' if stored history exists.
        Store merged history in config.
        """
        headers = {"Authorization": f"Bearer {accessToken}"}
        allRecords: List[Dict[str, Any]] = []
        page: int = 1
        pageSize: int = 50
        params: Dict[str, Union[int, str]] = {"pageSize": pageSize}
        if vin:
            params["vin"] = vin
            stored = loadConfig().get("charging_history", {}).get(vin, [])
            if stored:
                lastTime = stored[-1].get("chargeStartDateTime")
                if lastTime:
                    params["startTime"] = lastTime
                    logger.info(f"Using startTime={lastTime} for VIN {vin} based on stored history.")
        logger.info("Retrieving charging history...")
        while True:
            params["pageNo"] = page
            url = f"{baseUrl}/api/1/dx/charging/history"
            logger.debug(f"Fetching charging history: URL: {url} Headers: {redactSensitive(headers)} Params: {params}")
            try:
                resp = makeRequest("GET", url, headers, params=params)
            except Exception as e:
                logger.error(f"Network error fetching charging history (page {page}): {e}")
                break
            logger.debug(f"Response status: {resp.status_code} Data: {resp.text}")
            if resp.status_code == 401:
                logger.warning("Access token expired during history fetch.")
                return []
            if resp.status_code != 200:
                logger.error(f"Error fetching charging history (HTTP {resp.status_code}): {resp.text}")
                break
            recordsPage = self.parseChargingHistoryResponse(resp)
            if not recordsPage:
                break
            allRecords.extend(recordsPage)
            logger.info(f"Fetched {len(recordsPage)} records from page {page}.")
            if len(recordsPage) < pageSize:
                break
            page += 1
        logger.info(f"Total charging sessions retrieved: {len(allRecords)}")
        self.saveHistory(vin, allRecords)
        return allRecords

    def getInvoiceFilename(self, rec: Dict[str, Any]) -> str:
        """
        Generate the invoice filename in the form:
        YYYYMMDD.Tesla.Charging - <location> - <charging_usage>kWh.<currencySymbol><total_due>.pdf
        """
        chargeStart = rec.get("chargeStartDateTime")
        if chargeStart:
            try:
                dt = datetime.datetime.fromisoformat(chargeStart)
                dateStr = dt.strftime("%Y%m%d")
            except Exception:
                dateStr = "00000000"
        else:
            dateStr = "00000000"
        location = rec.get("siteLocationName", "Unknown")
        chargingUsage = 0.0
        totalDue = 0.0
        fees = rec.get("fees", [])
        for fee in fees:
            try:
                if fee.get("feeType") == "CHARGING" and fee.get("usageBase") is not None:
                    chargingUsage += float(fee.get("usageBase"))
            except Exception:
                pass
            try:
                if fee.get("totalDue") is not None:
                    totalDue += float(fee.get("totalDue"))
            except Exception:
                pass
        CURRENCY_SYMBOLS = {
            "AUD": "$",
            "USD": "$",
            "CAD": "$",
            "EUR": "€",
            "GBP": "£",
            "JPY": "¥",
            "CNY": "¥"
        }
        currencySymbol = ""
        if fees:
            currencyCode = fees[0].get("currencyCode", "")
            currencySymbol = CURRENCY_SYMBOLS.get(currencyCode, "")
        filename = f"{dateStr}.Tesla.Charging - {location} - {chargingUsage:.2f}kWh.{currencySymbol}{totalDue:.2f}.pdf"
        return safeFilename(filename)

    def downloadInvoices(self, records: List[Dict[str, Any]], vinFilter: Optional[str] = None, outputDir: str = ".") -> None:
        """
        Download PDF invoices for each record and save metadata.
        Files are saved to outputDir.
        """
        if not records:
            logger.info("No charging records to process for invoices.")
            return

        for rec in records:
            if vinFilter and rec.get("vin") != vinFilter:
                continue
            invoicesInfo = rec.get("invoices") or rec.get("Invoices")
            if not invoicesInfo:
                continue
            inv = invoicesInfo[0]
            invId = inv.get("contentId") or inv.get("id")
            if not invId:
                logger.warning("No invoice ID found for a record, skipping.")
                continue
            fileName = self.getInvoiceFilename(rec)
            filePath = os.path.join(outputDir, fileName)
            if os.path.exists(filePath):
                logger.info(f"Invoice {filePath} already exists. Skipping download.")
                continue
            config = loadConfig()
            baseUrl = getBaseUrlForRegion(config.get("region", "NA"))
            invoiceUrl = f"{baseUrl}/api/1/dx/charging/invoice/{invId}"
            logger.info(f"Downloading invoice PDF: {filePath}")
            logger.debug(f"Invoice URL: {invoiceUrl}")
            try:
                resp = makeRequest("GET", invoiceUrl, headers={"Authorization": f"Bearer {config.get('access_token')}"})
            except Exception as e:
                logger.error(f"Network error downloading invoice {filePath}: {e}")
                continue
            logger.debug(f"Response status: {resp.status_code} Data: {resp.text[:200]}")
            if resp.status_code != 200:
                logger.error(f"Failed to download invoice {invId} (HTTP {resp.status_code}): {resp.text}")
                continue
            try:
                with open(filePath, 'wb') as pdfFile:
                    pdfFile.write(resp.content)
                logger.info(f"Saved invoice PDF: {filePath}")
            except Exception as e:
                logger.error(f"Error saving PDF file {filePath}: {e}")
                continue
            metaName = os.path.splitext(filePath)[0] + ".json"
            try:
                with open(metaName, 'w') as metaFile:
                    json.dump(rec, metaFile, indent=4)
                logger.info(f"Saved invoice metadata: {metaName}")
            except Exception as e:
                logger.error(f"Error saving metadata file {metaName}: {e}")

def main(args: argparse.Namespace) -> None:
    if args.log_file:
        fileHandler = logging.FileHandler(args.log_file)
        fileFormatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
        fileHandler.setFormatter(fileFormatter)
        logger.addHandler(fileHandler)
        logger.info(f"Logging to file: {args.log_file}")
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug mode enabled.")

    if args.daemon:
        logger.info("Daemonising process...")
        daemonize()
        downloader = TeslaInvoiceDownloader(interactive=False)
        while True:
            accessToken = downloader.authenticate()
            baseUrl = getBaseUrlForRegion(downloader.config.get("region", "NA"))
            records = downloader.fetchChargingHistory(baseUrl, accessToken, vin=args.vin)
            if not records:
                logger.error("Failed to retrieve charging history. Skipping this cycle.")
            else:
                downloader.downloadInvoices(records, vinFilter=args.vin, outputDir=args.output_dir)
            logger.info("Cycle complete. Sleeping for one hour...")
            time.sleep(3600)
    else:
        downloader = TeslaInvoiceDownloader(interactive=True)
        accessToken = downloader.authenticate()
        baseUrl = getBaseUrlForRegion(downloader.config.get("region", "NA"))
        records = downloader.fetchChargingHistory(baseUrl, accessToken, vin=args.vin)
        if not records:
            logger.error("Failed to retrieve charging history. Exiting.")
            sys.exit(1)
        downloader.downloadInvoices(records, vinFilter=args.vin, outputDir=args.output_dir)
        logger.info("Done. All available invoices have been downloaded.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Tesla Invoice Downloader with HTTP Callback, Logging, and Daemonisation")
    parser.add_argument("--vin", help="Restrict to a particular VIN", default=None)
    parser.add_argument("--output-dir", help="Directory to save invoice files", default=".")
    parser.add_argument("--log-file", help="File to write logs to", default=None)
    parser.add_argument("--daemon", action="store_true", help="Daemonise the process to run in the background")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    main(args)
