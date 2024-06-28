import requests
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LocalNessusScanner:
    def __init__(self):
        self.url = "https://localhost:8834"
        self.verify = False  # Ignore SSL certificate verification
        self.access_key = "263043bbeb56b19c75f1242a66e40eb64afff1ea33154bd782a069edeff00cc6"
        self.secret_key = "4aa525d5bb9d966cada29442917b89168aa15c3ae3ca0193a86d1fef757ab3fa"
        self.session = requests.Session()
        self.session.headers.update({
            "X-ApiKeys": f"accessKey={self.access_key}; secretKey={self.secret_key}",
            "Content-Type": "application/json"
        })

    def test_connection(self):
        try:
            response = self.session.get(f"{self.url}/server/status", verify=self.verify)
            response.raise_for_status()
            print("Successfully connected to Nessus API")
        except requests.exceptions.RequestException as e:
            print(f"Failed to connect to Nessus API: {e}")
            raise

    def list_scan_templates(self):
        try:
            response = self.session.get(f"{self.url}/editor/policy/templates", verify=self.verify)
            response.raise_for_status()
            templates = response.json()['templates']
            for idx, template in enumerate(templates):
                print(f"{idx + 1}: {template['title']} ({template['uuid']})")
            return templates
        except requests.exceptions.RequestException as e:
            print(f"Failed to retrieve policy templates: {e}")
            raise

    def scan_network(self, network_range, template_uuid):
        try:
            # Create scan
            scan_data = {
                "uuid": template_uuid,
                "settings": {
                    "name": "Network Scan",
                    "enabled": True,
                    "text_targets": network_range,
                    "description": "Network scan created by LocalNessusScanner"
                }
            }
            print(f"Scan Data: {json.dumps(scan_data, indent=2)}")  # Debug information

            response = self.session.post(f"{self.url}/scans", json=scan_data, verify=self.verify)
            response.raise_for_status()
            scan_id = response.json()['scan']['id']
            
            # Launch scan
            response = self.session.post(f"{self.url}/scans/{scan_id}/launch", verify=self.verify)
            response.raise_for_status()
            print(f"Scan started successfully. Scan ID: {scan_id}")
            return scan_id
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to start Nessus scan. Check your API keys and permissions. Error: {e}")
            raise

    def get_scan_results(self, scan_id):
        try:
            response = self.session.get(f"{self.url}/scans/{scan_id}", verify=self.verify)
            response.raise_for_status()
            results = response.json()
            print(f"Results for scan ID {scan_id}: {json.dumps(results, indent=2)}")  # Debug information
            return results
        except requests.exceptions.RequestException as e:
            print(f"Failed to retrieve scan results for scan ID {scan_id}. Error: {e}")
            raise

# Example usage
if __name__ == "__main__":
    nessus_scanner = LocalNessusScanner()
    try:
        nessus_scanner.test_connection()
        templates = nessus_scanner.list_scan_templates()
        for idx, template in enumerate(templates):
            print(f"{idx + 1}: {template['title']} ({template['uuid']})")
        template_idx = int(input("Enter the number of the template to use for the scan: ")) - 1
        template_uuid = templates[template_idx]['uuid']
        network_range = input("Enter the network range to scan (e.g., 192.168.1.0/24): ")
        scan_id = nessus_scanner.scan_network(network_range, template_uuid)
        results = nessus_scanner.get_scan_results(scan_id)
    except Exception as e:
        print(f"An error occurred: {e}")
