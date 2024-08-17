# Import the nmap library for network scanning
import paramiko  # Import paramiko for SSH operations
import requests  # Import requests for HTTP requests
import smtplib  # Import smtplib for sending emails
from email.mime.text import MIMEText  # Import MIMEText for email formatting
from fpdf import FPDF  # Import FPDF for PDF generation
import time  # Import time for implementing sleep intervals
import json  # Import json for handling JSON data
import datetime  # Import datetime for timestamping
import ssl  # Import ssl for checking SSL encryption
import socket  # Import socket for creating network connections
import argparse  # Import argparse for command-line argument parsing

# 1. Automated Network Enumeration
def enumerate_network(ip_range):
    scanner = nmap.PortScanner()  # Initialize the nmap port scanner
    scanner.scan(hosts=ip_range, arguments='-O')  # Scan the network for OS and service information
    for host in scanner.all_hosts():  # Iterate over all discovered hosts
        print(f'Host: {host} ({scanner[host].hostname()})')  # Print the IP and hostname of the host
        # Print the detected OS or 'Unknown' if OS detection failed
        print(f'OS: {scanner[host]["osmatch"][0]["name"]}' if 'osmatch' in scanner[host] else 'OS: Unknown')
        print(f'State: {scanner[host].state()}')  # Print the state of the host (up/down)
        for proto in scanner[host].all_protocols():  # Iterate over all detected protocols (e.g., TCP, UDP)
            print(f'Protocol: {proto}')  # Print the protocol name
            lport = scanner[host][proto].keys()  # Get the list of open ports
            for port in lport:  # Iterate over all open ports
                print(f'Port: {port}\tState: {scanner[host][proto][port]["state"]}')  # Print port number and state

# 2. Credential Dump Detection
def check_password_breach(password):
    # Query the pwnedpasswords API for the first 5 characters of the hashed password
    response = requests.get(f'https://api.pwnedpasswords.com/range/{password[:5]}')
    # Parse the response to check if the password hash is in the leaked dataset
    hashes = (line.split(':') for line in response.text.splitlines())
    return any(password[5:].upper() == hash for hash, _ in hashes)  # Return True if a match is found

def brute_force_with_breach_check(target, username, passwords):
    ssh = paramiko.SSHClient()  # Initialize SSH client
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # Automatically accept unknown host keys
    for password in passwords:  # Iterate over the list of passwords
        if check_password_breach(password):  # Check if the password has been leaked
            print(f'Password {password} has been found in a breach.')  # Alert if the password is compromised
        try:
            ssh.connect(target, username=username, password=password)  # Attempt to connect via SSH
            print(f'Successfully logged in with password: {password}')  # Notify of successful login
            break  # Stop further attempts after a successful login
        except paramiko.AuthenticationException:  # Catch failed login attempts
            print(f'Failed to login with password: {password}')  # Notify of failed login
    ssh.close()  # Close the SSH connection

# 3. Active Port Monitoring
def monitor_ports(ip, interval=60):
    scanner = nmap.PortScanner()  # Initialize the nmap port scanner
    known_ports = {}  # Initialize an empty dictionary to track known ports
    while True:  # Start an infinite loop for continuous monitoring
        scanner.scan(ip, arguments='-p-')  # Scan all ports on the target IP
        current_ports = scanner[ip]['tcp'].keys()  # Get the list of currently open ports
        new_ports = set(current_ports) - set(known_ports.keys())  # Identify newly opened ports
        closed_ports = set(known_ports.keys()) - set(current_ports)  # Identify recently closed ports
        
        if new_ports:  # Check if there are any new open ports
            print(f'New open ports detected: {new_ports}')  # Notify of new ports
        if closed_ports:  # Check if any ports were closed
            print(f'Ports closed: {closed_ports}')  # Notify of closed ports
        
        # Update known_ports with the current state of all ports
        known_ports = {port: scanner[ip]['tcp'][port]['state'] for port in current_ports}
        time.sleep(interval)  # Wait for the specified interval before rescanning

# 4. Alert System for Critical Vulnerabilities
def send_alert(subject, body):
    msg = MIMEText(body)  # Create an email message with the provided body text
    msg['Subject'] = subject  # Set the subject of the email
    msg['From'] = 'your-email@example.com'  # Set the sender's email address
    msg['To'] = 'admin@example.com'  # Set the recipient's email address

    with smtplib.SMTP('smtp.example.com') as server:  # Connect to the SMTP server
        server.login('your-email@example.com', 'password')  # Log in to the SMTP server
        server.sendmail('your-email@example.com', 'admin@example.com', msg.as_string())  # Send the email

def scan_and_alert(ip_range):
    scanner = nmap.PortScanner()  # Initialize the nmap port scanner
    scanner.scan(hosts=ip_range, arguments='--script vuln')  # Scan the network for vulnerabilities using nmap scripts
    for host in scanner.all_hosts():  # Iterate over all discovered hosts
        vulnerabilities = scanner[host].get('hostscript', [])  # Retrieve any found vulnerabilities
        if vulnerabilities:  # Check if any vulnerabilities were found
            # Format the vulnerabilities into a string for email alerting
            vuln_info = "\n".join([f"{vuln['id']}: {vuln['output']}" for vuln in vulnerabilities])
            send_alert(f'Critical vulnerabilities found on {host}', vuln_info)  # Send an alert email

# 5. Comprehensive Report Generation
class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)  # Set font for the header
        self.cell(0, 10, 'Network Security Analysis Report', 0, 1, 'C')  # Add the report title to the header

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)  # Set font for chapter titles
        self.cell(0, 10, title, 0, 1, 'L')  # Add the chapter title
        self.ln(5)  # Add a line break

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)  # Set font for the body text
        self.multi_cell(0, 10, body)  # Add the body text
        self.ln()  # Add a line break

    def add_chapter(self, title, body):
        self.add_page()  # Add a new page for the chapter
        self.chapter_title(title)  # Add the chapter title
        self.chapter_body(body)  # Add the chapter body text

def generate_report(findings):
    pdf = PDFReport()  # Initialize the PDF report
    pdf.add_chapter('Network Scan Summary', findings)  # Add a chapter for the network scan summary
    pdf.output('network_security_report.pdf')  # Output the PDF report to a file

# 6. Historical Vulnerability Tracking
def save_vulnerabilities(host, vulnerabilities):
    history = {}  # Initialize an empty dictionary to store vulnerability history
    try:
        with open('vulnerability_history.json', 'r') as file:  # Attempt to open the existing history file
            history = json.load(file)  # Load the history from the file
    except FileNotFoundError:  # Handle the case where the file doesn't exist
        pass

    date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Get the current date and time as a string
    # Append the new vulnerabilities to the history for the given host
    history[host] = history.get(host, []) + [{date: vulnerabilities}]

    with open('vulnerability_history.json', 'w') as file:  # Open the history file for writing
        json.dump(history, file, indent=4)  # Save the updated history back to the file

def scan_vulnerabilities(ip):
    scanner = nmap.PortScanner()  # Initialize the nmap port scanner
    scanner.scan(hosts=ip, arguments='--script vuln')  # Scan the target IP for vulnerabilities
    vulnerabilities = scanner[ip].get('hostscript', [])  # Retrieve the list of vulnerabilities
    save_vulnerabilities(ip, vulnerabilities)  # Save the vulnerabilities to the history
    return vulnerabilities  # Return the list of vulnerabilities


# 7. Data Encryption Detection
def check_ssl(hostname, port=443):
    context = ssl.create_default_context()  # Create a default SSL context
    try:
        with socket.create_connection((hostname, port)) as sock:  # Establish a connection to the server
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:  # Wrap the connection in SSL
                cert = ssock.getpeercert()  # Get the SSL certificate from the server
                print(f'SSL Certificate for {hostname}:')  # Print the SSL certificate details
                for key, value in cert.items():  # Iterate over each item in the certificate
                    print(f'{key}: {value}')  # Print the key-value pairs
    except ssl.SSLError as e:  # Handle SSL errors
        print(f'SSL error: {e}')  # Print the SSL error message
    except Exception as e:  # Handle any other exceptions
        print(f'Error connecting to {hostname}:{port} - {e}')  # Print the error message

def ssl_vulnerability_scan(hostname):
    scanner = nmap.PortScanner()  # Initialize the nmap port scanner
    scanner.scan(hosts=hostname, arguments='--script ssl-enum-ciphers -p 443')  # Run SSL cipher scan on port 443
    for host in scanner.all_hosts():  # Iterate over all discovered hosts
        if 'ssl-enum-ciphers' in scanner[host]['tcp'][443]:  # Check if the SSL cipher scan results are available
            # Print the cipher scan results
            print(f'SSL Cipher Scan for {host}: {scanner[host]["tcp"][443]["ssl-enum-ciphers"]}')
