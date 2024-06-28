import unittest
from toolbox.discovery import discover_hosts, discover_services

class TestDiscovery(unittest.TestCase):

    def test_discover_hosts(self):
        hosts = discover_hosts('192.168.1.0/24')
        self.assertTrue(len(hosts) > 0)

    def test_discover_services(self):
        services = discover_services('192.168.1.1')
        self.assertIn('http', services.keys())

if __name__ == '__main__':
    unittest.main()
