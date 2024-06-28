import time
from tqdm import tqdm
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.errors import GvmResponseError
import base64
import os
import logging

# Configuration
GMP_USERNAME = 'kali'
GMP_PASSWORD = 'kali'
GMP_HOST = '0.0.0.0'
GMP_PORT = 9390

SCAN_PROFILE = {"name": "Full and fast", "id": "daba56c8-73ec-11df-a475-002264764cea"}
PORT_LIST_ID = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'
SCANNER_ID = '08b69003-5fc2-4037-a479-93b440211c73'
PDF_REPORT_FORMAT_ID = 'c402cc3e-b531-11e1-9163-406186ea4fc5'  # Correct PDF report format ID

REPORT_DIR = "rapport"
if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

logger = logging.getLogger(__name__)

def get_target_id(gmp, target_ip):
    targets = gmp.get_targets().xpath('target')
    for target in targets:
        if target.find('hosts').text == target_ip:
            return target.get('id')
    return None

def get_task_status(gmp, task_id):
    task = gmp.get_task(task_id=task_id)
    status = task.find('task').find('status').text
    progress = int(task.find('task').find('progress').text)
    return status, progress

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

def generate_pdf_report(gmp, report_id, filename):
    try:
        response = gmp.get_report(report_id=report_id, report_format_id=PDF_REPORT_FORMAT_ID)
        report = response.find('report')
        if report is None:
            print("No report found.")
            return

        content = report.find('report_format').tail
        if content is None:
            print("No report content found. Please check the report format ID.")
            return

        pdf_content = base64.b64decode(content)
        with open(filename, 'wb') as pdf_file:
            pdf_file.write(pdf_content)
        print(f"PDF report generated: {filename}")
    except Exception as e:
        print(f"An error occurred while generating the PDF report: {e}")

class OpenVASScanner:
    def __init__(self, hostname, port, username, password):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password

    def scan(self, target_ip):
        connection = TLSConnection(hostname=self.hostname, port=self.port)
        transform = EtreeCheckCommandTransform()
        with Gmp(connection, transform=transform) as gmp:
            gmp.authenticate(self.username, self.password)

            scan_config_id = SCAN_PROFILE['id']

            target_id = get_target_id(gmp, target_ip)
            if target_id is None:
                try:
                    target_id = gmp.create_target(name=f'Target {target_ip}', hosts=[target_ip], port_list_id=PORT_LIST_ID).get('id')
                except GvmResponseError as e:
                    if "Target exists already" in str(e):
                        target_id = get_target_id(gmp, target_ip)
                    else:
                        raise

            task_name = f"Task {target_ip}"
            task_response = gmp.create_task(
                name=task_name,
                config_id=scan_config_id,
                target_id=target_id,
                scanner_id=SCANNER_ID
            )
            task_id = task_response.xpath('//@id')[0]

            print(f"Wizard scan lancer sur {target_ip} avec la task ID: {task_id}")

            gmp.start_task(task_id)
            
            wait_for_task_completion(gmp, task_id)

            print("Analyse terminée. Attendre 5 secondes avant le téléchargement du rapport...")
            time.sleep(5)

            task_response = gmp.get_task(task_id=task_id)
            report_id = task_response.xpath('//last_report/report/@id')[0]

            print(f'Scan started. Report ID: {report_id}')
            
            # Generate PDF report
            pdf_filename = os.path.join(REPORT_DIR, f"scan_report_{report_id}.pdf")
            generate_pdf_report(gmp, report_id, pdf_filename)
            return pdf_filename
