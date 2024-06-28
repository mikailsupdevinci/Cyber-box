import subprocess
import os
from datetime import datetime
import time
import progressbar

def run_nikto_scan(target_url, output_dir):
    # Ensure the output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Generate a filename based on date and time
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = os.path.join(output_dir, f'nikto_scan_{timestamp}.txt')

    # Command to run Nikto with the -h option
    command = [
        'nikto', '-h', target_url,
        '-output', output_file
    ]

    # Initialize the timer
    start_time = time.time()

    # Start the progress bar
    print("Starting Nikto scan...")
    with progressbar.ProgressBar(max_value=100) as bar:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            while process.poll() is None:
                time.sleep(1)
                elapsed_time = time.time() - start_time
                # Update the progress bar every second
                bar.update(min(100, int(elapsed_time * 100 / 600)))  # 600 seconds = 10 minutes
            
            stdout, stderr = process.communicate()

            if stdout:
                print(stdout.decode())
            if stderr:
                print(stderr.decode())
                
            if process.returncode == 0:
                print(f'Scan completed successfully. Results saved in {output_file}')
            else:
                print(f'Error executing Nikto: {stderr.decode()}')

        except subprocess.CalledProcessError as e:
            print(f'Error executing Nikto: {e}')

        elapsed_time = time.time() - start_time
        print(f"Elapsed time: {elapsed_time:.2f} seconds")

def nikto_scan(target_url):
    output_dir = 'nikto_results'
    run_nikto_scan(target_url, output_dir)
    return {"output_directory": output_dir}
