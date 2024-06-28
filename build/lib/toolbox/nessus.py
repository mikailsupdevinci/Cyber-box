from tenable.io import TenableIO
from tenable.errors import UnauthorizedError

class NessusScanner:
    def __init__(self):
        # Définir les clés API directement dans le code
        access_key = 'a06faf62e3e8a7ec5b4c5f6f5272d95a731af11f2c45b86abfee4d539d9cb4e8'
        secret_key = '323e071e52e63b01fdb6969ee8a735606dcfcab767d615869354b1cb764297af'
        
        # Initialiser le client TenableIO avec les clés API
        self.client = TenableIO(access_key, secret_key)

    def scan_network(self, network_range):
        try:
            # Créer un scan dans Nessus
            scan = self.client.scans.create(
                name='Network Scan',
                targets=[network_range],
                template='basic',
            )
            # Lancer le scan
            self.client.scans.launch(scan['id'])
            return scan['id']
        except UnauthorizedError as e:
            print(f"Unauthorized error: {e}")
            return None

    def get_scan_results(self, scan_id):
        try:
            # Récupérer les résultats du scan
            results = self.client.scans.results(scan_id)
            return results
        except UnauthorizedError as e:
            print(f"Unauthorized error: {e}")
            return None
