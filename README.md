# VirusTotal URL Scanner

## Introduction
This tool allows users to check if a URL is flagged as malicious using the VirusTotal API. It submits a URL for scanning and retrieves the analysis results.

---

## Step 1: Understand VirusTotal's API
VirusTotal provides a [public API](https://developers.virustotal.com/reference/overview) to scan URLs, domains, files, and IP addresses. This tool focuses on:

- **URL scanning**: Submit a URL to check if it’s malicious.
- **Domain reputation**: Analyze a domain’s historical data.

**Key Endpoints**:

- `POST /urls`: Submit a URL for scanning.
- `GET /urls/{id}`: Retrieve scan results.
- `GET /domains/{domain}`: Fetch domain reputation data.

---

## Step 2: Get a VirusTotal API Key

1. Sign up for a [VirusTotal account](https://www.virustotal.com/gui/join-us).
2. Navigate to your profile to find your **API key**.
3. **Note**: Free-tier accounts have limited API requests per minute (e.g., 500/day, 4/min).

---

## Step 3: Install Dependencies

Before running the script, install the required dependencies:

```bash
pip install requests
```

---

## Step 4: Run the Tool

1. Replace `YOUR_API_KEY` in the script with your VirusTotal API key.
2. Run the script:

```bash
python virustotal_scanner.py
```

3. Enter a URL to check (e.g., `http://example.com`).
4. The tool will display the number of security vendors flagging the URL as malicious.

---

## Notes
- This tool uses a **15-second delay** to allow VirusTotal to process the scan.
- Ensure you do not exceed the API rate limits.
- Results will include statistics such as **malicious**, **suspicious**, and **undetected** counts.

---

## Disclaimer
This tool is intended for **educational and security research purposes only**. Use responsibly and comply with all **legal and ethical** guidelines.

