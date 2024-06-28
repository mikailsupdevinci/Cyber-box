import sys
import logging
import json
import time
from tqdm import tqdm
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmResponseError
import base64
import paramiko
from toolbox.discovery import discover_hosts, discover_services, os_detection, parallel_scan
from toolbox.vulnerability_detection import nmap_vuln_scan, http_headers_analysis, nikto_scan, scan_specific_vulnerabilities
from toolbox.password_analysis import analyze_password_strength
from toolbox.authentication_tests import test_authentication
from toolbox.exploit import exploit_vulnerability, exploit_vulnerability_with_metasploit
from toolbox.post_exploit import post_exploit_analysis
from toolbox.reporting import generate_report

# Configuration for OpenVAS
GMP_USERNAME = 'kali'
GMP_PASSWORD = 'kali'
GMP_HOST = '0.0.0.0'
GMP_PORT = 9390

PORT_LIST_ID = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
PDF_REPORT_FORMAT_ID = 'c402cc3e-b531-11e1-9163-406186ea4fc5'
SCAN_PROFILE = {"name": "Full and fast", "id": "daba56c8-73ec-11df-a475-002264764cea"}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def print_ascii_art():
    art = """
    _________        ___.                         __________              
    \_   ___ \___.__.\_ |__   ___________         \______   \ _______  ___
    /    \  \<   |  | | __ \_/ __ \_  __ \  ______ |    |  _//  _ \  \/  /
    \     \___\___  | | \_\ \  ___/|  | \/ /_____/ |    |   (  <_> >    < 
     \______  / ____| |___  /\___  >__|            |______  /\____/__/\_ \
            \/\/          \/     \/                       \/            \/
    """
    print(art)
    print("\nCopyright Mikail ALBAYRAK")
    print("Toute utilisation de cette toolbox à mauvais escient pourrait avoir des répercussions.")
    print("Cette toolbox est dédiée à un usage personnel.\n")

def print_menu():
    print("\nWelcome to the Intrusion Toolbox")
    print("Please choose an option:")
    print("1. Scans and Vulnerability Detection")
    print("2. Analyze Password Strength")
    print("3. Test Authentication")
    print("4. Exploit Vulnerabilities")
    print("5. Post-Exploit Analysis")
    print("6. Generate Report")
    print("7. Automatic Pentest Workflow")
    print("8. SSH Brute Force Attack")
    print("9. Exit")

def print_scan_vuln_menu():
    print("\nScan and Vulnerability Detection Options")
    print("1. Discover Hosts")
    print("2. Discover Services")
    print("3. OS Detection")
    print("4. Scan Specific Vulnerabilities")
    print("5. Nmap Vulnerability Scan")
    print("6. HTTP Headers Analysis")
    print("7. Nikto Web Scan")
    print("8. OpenVAS Network Scan")
    print("9. Run All")
    print("10. Back to Main Menu")

def format_result(title, data):
    print(f"\n{'='*20} {title} {'='*20}")
    print(data)
    print('='*60)

def openvas_network_scan(target):
    try:
        connection = TLSConnection(hostname=GMP_HOST, port=GMP_PORT)
        transform = EtreeCheckCommandTransform()
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(GMP_USERNAME, GMP_PASSWORD)
            scan_config_id = SCAN_PROFILE['id']
            
            target_id = get_target_id(gmp, target)
            if target_id is None:
                target_id = gmp.create_target(name=f'Target {target}', hosts=[target], port_list_id=PORT_LIST_ID).get('id')

            task_id = gmp.create_task(name=f"Task {target}", config_id=scan_config_id, target_id=target_id, scanner_id=SCANNER_ID).xpath('//@id')[0]
            gmp.start_task(task_id)
            wait_for_task_completion(gmp, task_id)
            report_id = gmp.get_task(task_id=task_id).xpath('//last_report/report/@id')[0]
            return gmp.get_report(report_id=report_id)
    except Exception as e:
        logger.error(f"OpenVAS scan failed: {e}")
        return {"error": str(e)}

def get_target_id(gmp, target_ip):
    targets = gmp.get_targets().xpath('target')
    for target in targets:
        if target.find('hosts').text == target_ip:
            return target.get('id')
    return None

def wait_for_task_completion(gmp, task_id):
    with tqdm(total=100, desc="Scan Progress", bar_format='{l_bar}{bar} [ time left: {remaining} ]') as pbar:
        while True:
            task_status, task_progress = get_task_status(gmp, task_id)
            pbar.n = task_progress
            pbar.refresh()
            print(f"\rStatut de la tache: {task_status}, Progress: {task_progress}%", end="")
            if task_status == 'Done':
                break
            elif task_status == 'Stopped':
                print("La tache a été arreté")
                return
            time.sleep(10)
    print()  # For newline after progress completion

def get_task_status(gmp, task_id):
    task = gmp.get_task(task_id=task_id)
    status = task.find('task').find('status').text
    progress = int(task.find('task').find('progress').text)
    return status, progress

def run_all_scans_and_vulns(target):
    print(f"Running all scans and vulnerability detection on {target}")
    tasks = [
        ("Discover Services", discover_services),
        ("OS Detection", os_detection),
        ("Scan Specific Vulnerabilities", scan_specific_vulnerabilities),
        ("Nmap Vulnerability Scan", nmap_vuln_scan),
        ("HTTP Headers Analysis", http_headers_analysis),
        ("Nikto Web Scan", nikto_scan),
        ("OpenVAS Network Scan", openvas_network_scan)
    ]

    results = {}

    for task_name, task_func in tqdm(tasks, desc="Running Scans", unit="scan"):
        print(f"Starting {task_name}...")
        try:
            if task_name == "HTTP Headers Analysis" or task_name == "Nikto Web Scan":
                result = task_func(f"http://{target}")
            else:
                result = task_func(target)
            results[task_name] = result
            format_result(task_name, result)
        except Exception as e:
            logger.error(f"{task_name} failed: {e}")
            results[task_name] = {"error": str(e)}

    return results

def automatic_pentest_workflow():
    choice = input("Do you want to scan a network or a specific IP? (Enter 'network' or 'IP'): ").strip().lower()
    if choice == 'network':
        target = input("Enter the network to scan (e.g., 192.168.1.0/24): ")
        hosts = discover_hosts(target)
        print(f"Discovered hosts: {hosts}")
    elif choice == 'ip':
        target = input("Enter the IP address to scan: ")
        hosts = [target]
    else:
        print("Invalid choice. Please enter 'network' or 'IP'.")
        return

    print("Starting Automatic Pentest Workflow")
    pentest_results = {}

    # Parallel scan for services
    services = parallel_scan(hosts, discover_services)
    for host, service in services.items():
        pentest_results[host] = {'services': service, 'os_info': None, 'vulnerabilities': {}, 'exploit_results': {}, 'post_exploit_data': None}
        format_result(f"Services on {host}", service)

    # Parallel scan for OS detection
    os_info = parallel_scan(hosts, os_detection)
    for host, os_info in os_info.items():
        pentest_results[host]['os_info'] = os_info
        format_result(f"OS Information for {host}", os_info)

    # Parallel vulnerability scan
    vuln_scans = parallel_scan(hosts, nmap_vuln_scan)
    for host, vulnerabilities in vuln_scans.items():
        pentest_results[host]['vulnerabilities'] = vulnerabilities
        format_result(f"Vulnerabilities on {host}", vulnerabilities)

    # Parallel HTTP headers analysis
    http_vulns = parallel_scan(hosts, http_headers_analysis)
    for host, vulnerabilities in http_vulns.items():
        pentest_results[host]['vulnerabilities']['http_headers'] = vulnerabilities
        format_result(f"HTTP Headers Analysis on {host}", vulnerabilities)

    # Parallel Nikto scan
    nikto_results = parallel_scan(hosts, nikto_scan)
    for host, vulnerabilities in nikto_results.items():
        pentest_results[host]['vulnerabilities']['nikto'] = vulnerabilities
        format_result(f"Nikto Scan on {host}", vulnerabilities)

    # OpenVAS scan
    for host in tqdm(hosts, desc="Running OpenVAS Scans", unit="scan"):
        openvas_results = openvas_network_scan(host)
        pentest_results[host]['vulnerabilities']['openvas'] = openvas_results
        format_result(f"OpenVAS Scan Results for {host}", openvas_results)

    # Exploit vulnerabilities (example using Metasploit)
    for host, data in pentest_results.items():
        for vuln_id in data['vulnerabilities']:
            result = exploit_vulnerability_with_metasploit(vuln_id, host)
            pentest_results[host]['exploit_results'][vuln_id] = result
            format_result(f"Exploitation result for {vuln_id} on {host}", result)

    # Post-exploit analysis
    post_exploit_data = parallel_scan(hosts, post_exploit_analysis)
    for host, sensitive_data in post_exploit_data.items():
        pentest_results[host]['post_exploit_data'] = sensitive_data
        format_result(f"Sensitive data found on {host}", sensitive_data)

    # Generate report
    report_path = "pentest_report.json"
    with open(report_path, 'w') as report_file:
        json.dump(pentest_results, report_file, indent=4)
    print(f"Pentest report generated at {report_path}")

def ssh_brute_force(target, username_file, password_file):
    with open(username_file, 'r') as uf, open(password_file, 'r') as pf:
        usernames = [line.strip() for line in uf]
        passwords = [line.strip() for line in pf]
    
    for username in usernames:
        for password in passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(target, username=username, password=password)
                print(f"Successful login: {username}@{target} with password: {password}")
                ssh.close()
                return
            except paramiko.AuthenticationException:
                continue
            except Exception as e:
                print(f"Error: {e}")
                return
    print("Brute force attack failed. No valid credentials found.")

def main():
    print_ascii_art()
    while True:
        print_menu()
        choice = input("Enter your choice: ")

        if choice == '1':
            while True:
                print_scan_vuln_menu()
                scan_choice = input("Enter your choice: ")

                if scan_choice == '1':
                    network_range = input("Enter the network range to discover hosts (e.g., 192.168.1.0/24): ")
                    hosts = discover_hosts(network_range)
                    format_result("Discovered Hosts", hosts)
                elif scan_choice == '2':
                    target = input("Enter the IP address or network to discover services: ")
                    services = discover_services(target)
                    format_result("Discovered Services", services)
                elif scan_choice == '3':
                    target = input("Enter the IP address or network for OS detection: ")
                    os_info = os_detection(target)
                    format_result("OS Information", os_info)
                elif scan_choice == '4':
                    target = input("Enter the IP address or network to scan for specific vulnerabilities: ")
                    vulnerabilities = scan_specific_vulnerabilities(target)
                    format_result("Specific Vulnerabilities", vulnerabilities)
                elif scan_choice == '5':
                    target = input("Enter the IP address or network to scan with Nmap: ")
                    vulnerabilities = nmap_vuln_scan(target)
                    format_result("Nmap Vulnerability Scan", vulnerabilities)
                elif scan_choice == '6':
                    url = input("Enter the URL for HTTP headers analysis: ")
                    vulnerabilities = http_headers_analysis(url)
                    format_result("HTTP Headers Analysis", vulnerabilities)
                elif scan_choice == '7':
                    url = input("Enter the URL for Nikto web scan: ")
                    vulnerabilities = nikto_scan(url)
                    format_result(f"Nikto Web Scan for {url}", vulnerabilities)
                elif scan_choice == '8':
                    target_ip = input("Please enter the IP address of the target to scan: ")
                    try:
                        result = openvas_network_scan(target_ip)
                        format_result("OpenVAS Scan Results", result)
                    except Exception as e:
                        logger.error(f"OpenVAS scan failed: {e}")
                elif scan_choice == '9':
                    target = input("Enter the IP address or network to scan: ")
                    run_all_scans_and_vulns(target)
                elif scan_choice == '10':
                    break
                else:
                    print("Invalid choice, please try again.")
        elif choice == '2':
            passwords = input("Enter passwords to analyze (comma-separated): ").split(',')
            weak_passwords = analyze_password_strength(passwords)
            format_result("Weak passwords", weak_passwords)
        elif choice == '3':
            url = input("Enter the URL for authentication test: ")
            username = input("Enter the username: ")
            password = input("Enter the password: ")
            is_authenticated = test_authentication(url, username, password)
            format_result(f"Authentication result for {url}", 'successful' if is_authenticated else 'failed')
        elif choice == '4':
            vulnerability = input("Enter vulnerability to exploit: ")
            result = exploit_vulnerability(vulnerability)
            format_result(f"Exploitation result for {vulnerability}", result)
        elif choice == '5':
            system_info = input("Enter system info for post-exploit analysis: ")
            sensitive_data = post_exploit_analysis(system_info)
            format_result(f"Sensitive data found for {system_info}", sensitive_data)
        elif choice == '6':
            results = input("Enter results to generate report: ")
            report_path = input("Enter the report file path: ")
            generate_report(results, report_path)
            print(f"Report generated at {report_path}")
        elif choice == '7':
            automatic_pentest_workflow()
        elif choice == '8':
            target = input("Enter the IP address of the target: ")
            username_file = input("Enter the path to the username file: ")
            password_file = input("Enter the path to the password file: ")
            ssh_brute_force(target, username_file, password_file)
        elif choice == '9':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
