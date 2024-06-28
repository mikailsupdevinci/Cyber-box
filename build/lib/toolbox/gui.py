import tkinter as tk
from tkinter import ttk, messagebox
from toolbox.discovery import discover_hosts, discover_services
from toolbox.vulnerability_detection import check_vulnerabilities
from toolbox.password_analysis import analyze_password_strength
from toolbox.authentication_tests import test_authentication
from toolbox.exploit import exploit_vulnerability
from toolbox.post_exploit import post_exploit_analysis
from toolbox.reporting import generate_report

class IntrusionToolboxApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Intrusion Toolbox")
        self.geometry("500x400")
        self.style = ttk.Style(self)
        self.style.theme_use('clam')

        self.create_widgets()

    def create_widgets(self):
        self.label = ttk.Label(self, text="Welcome to the Intrusion Toolbox", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.discovery_button = ttk.Button(self, text="Discover Hosts", command=self.discover_hosts)
        self.discovery_button.pack(pady=5)

        self.services_button = ttk.Button(self, text="Discover Services", command=self.discover_services)
        self.services_button.pack(pady=5)

        self.vulnerabilities_button = ttk.Button(self, text="Check Vulnerabilities", command=self.check_vulnerabilities)
        self.vulnerabilities_button.pack(pady=5)

        self.password_analysis_button = ttk.Button(self, text="Analyze Password Strength", command=self.analyze_password_strength)
        self.password_analysis_button.pack(pady=5)

        self.authentication_button = ttk.Button(self, text="Test Authentication", command=self.test_authentication)
        self.authentication_button.pack(pady=5)

        self.exploit_button = ttk.Button(self, text="Exploit Vulnerabilities", command=self.exploit_vulnerability)
        self.exploit_button.pack(pady=5)

        self.post_exploit_button = ttk.Button(self, text="Post-Exploit Analysis", command=self.post_exploit_analysis)
        self.post_exploit_button.pack(pady=5)

        self.report_button = ttk.Button(self, text="Generate Report", command=self.generate_report)
        self.report_button.pack(pady=5)

    def discover_hosts(self):
        network = self.get_input("Enter the network to scan (e.g., 192.168.1.0/24):")
        if network:
            hosts = discover_hosts(network)
            messagebox.showinfo("Discovered Hosts", f"Hosts: {hosts}")

    def discover_services(self):
        host = self.get_input("Enter the host to scan for services:")
        if host:
            services = discover_services(host)
            messagebox.showinfo("Discovered Services", f"Services: {services}")

    def check_vulnerabilities(self):
        service_info = self.get_input("Enter service info to check vulnerabilities:")
        if service_info:
            vulnerabilities = check_vulnerabilities(service_info)
            messagebox.showinfo("Vulnerabilities", f"Vulnerabilities: {vulnerabilities}")

    def analyze_password_strength(self):
        passwords = self.get_input("Enter passwords to analyze (comma-separated):")
        if passwords:
            passwords_list = passwords.split(',')
            weak_passwords = analyze_password_strength(passwords_list)
            messagebox.showinfo("Weak Passwords", f"Weak Passwords: {weak_passwords}")

    def test_authentication(self):
        url = self.get_input("Enter the URL for authentication test:")
        username = self.get_input("Enter the username:")
        password = self.get_input("Enter the password:")
        if url and username and password:
            is_authenticated = test_authentication(url, username, password)
            messagebox.showinfo("Authentication Result", f"Authentication {'successful' if is_authenticated else 'failed'}")

    def exploit_vulnerability(self):
        vulnerability = self.get_input("Enter vulnerability to exploit:")
        if vulnerability:
            result = exploit_vulnerability(vulnerability)
            messagebox.showinfo("Exploitation Result", f"Result: {result}")

    def post_exploit_analysis(self):
        system_info = self.get_input("Enter system info for post-exploit analysis:")
        if system_info:
            sensitive_data = post_exploit_analysis(system_info)
            messagebox.showinfo("Sensitive Data", f"Sensitive Data: {sensitive_data}")

    def generate_report(self):
        results = self.get_input("Enter results to generate report:")
        report_path = self.get_input("Enter the report file path:")
        if results and report_path:
            generate_report(results, report_path)
            messagebox.showinfo("Report Generated", f"Report generated at {report_path}")

    def get_input(self, prompt):
        input_window = tk.Toplevel(self)
        input_window.title("Input")
        
        ttk.Label(input_window, text=prompt).pack(pady=10)
        entry = ttk.Entry(input_window)
        entry.pack(pady=5)
        
        input_value = tk.StringVar()

        def on_submit():
            input_value.set(entry.get())
            input_window.destroy()

        submit_button = ttk.Button(input_window, text="Submit", command=on_submit)
        submit_button.pack(pady=10)
        
        self.wait_window(input_window)
        return input_value.get()

def main():
    app = IntrusionToolboxApp()
    app.mainloop()

if __name__ == "__main__":
    main()
