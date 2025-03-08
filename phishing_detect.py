import requests
import time

# VirusTotal API Configuration
API_KEY = "YOUR_API_KEY"  # Replace with your API key
URL_SCAN_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
URL_REPORT_ENDPOINT = "https://www.virustotal.com/api/v3/urls/{id}"
HEADERS = {"x-apikey": API_KEY}  # Removed Content-Type

def scan_url(url):
    # Submit URL as form data (multipart/form-data)
    files = {"url": (None, url)}  # Format for multipart upload
    response = requests.post(URL_SCAN_ENDPOINT, headers=HEADERS, files=files)
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        return analysis_id.split("-")[1]
    else:
        print(f"Error submitting URL: {response.text}")
        return None

def get_report(analysis_id):
    # Fetch scan results
    response = requests.get(
        URL_REPORT_ENDPOINT.format(id=analysis_id),
        headers=HEADERS
    )
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching report: {response.text}")
        return None

def main():
    url = input("Enter the URL to check: ")
    analysis_id = scan_url(url)
    if analysis_id:
        print("Scanning URL... (this may take a moment)")
        time.sleep(15)  # Wait for VirusTotal to process the scan
        report = get_report(analysis_id)
        if report:
            stats = report["data"]["attributes"]["last_analysis_stats"]
            print(f"\nResults for {url}:")
            print(f"Malicious: {stats['malicious']}")
            print(f"Suspicious: {stats['suspicious']}")
            print(f"Undetected: {stats['undetected']}")

if __name__ == "__main__":
    main()




