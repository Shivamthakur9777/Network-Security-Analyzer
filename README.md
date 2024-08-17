Network Security Analyzer
This project is a comprehensive Network Security Analyzer that automates various security checks and assessments. It provides functionality for network enumeration, credential dump detection, port monitoring, SSL vulnerability scanning, and more. The tool also generates detailed PDF reports based on the findings and tracks vulnerabilities over time, making it a valuable resource for IT security professionals and enthusiasts.

Key Features:
Automated Network Enumeration: Scans a network range and identifies hosts, operating systems, and open ports.
Credential Breach Detection & SSH Brute Forcing: Checks passwords against known breaches and attempts SSH login with the given credentials.
Port Monitoring: Continuously monitors open/closed ports and detects any changes.
Alert System for Critical Vulnerabilities: Scans for vulnerabilities and sends automated email alerts for critical issues.
PDF Report Generation: Outputs a detailed report summarizing the analysis.
SSL/TLS Encryption Check: Analyzes SSL/TLS encryption and detects weak ciphers.
Installation Instructions
Follow these steps to set up and run the Network Security Analyzer on your local machine:

1. Clone the Repository
bash
Copy code
git clone https://github.com/your-username/network-security-analyzer.git
cd network-security-analyzer
2. Set Up a Virtual Environment (Optional but Recommended)
Create a virtual environment to manage dependencies:

bash
Copy code
python -m venv .venv
Activate the virtual environment:

Windows:
bash
Copy code
.venv\Scripts\activate
macOS/Linux:
bash
Copy code
source .venv/bin/activate
3. Install the Required Packages
Use pip to install all the dependencies listed in requirements.txt:

bash
Copy code
pip install -r requirements.txt
If you don’t have a requirements.txt file yet, you can create one using:

bash
Copy code
pip freeze > requirements.txt
4. Run the Script
Once everything is set up, you can start using the tool by running the main Python script:

bash
Copy code
python network_security_analysis.py
5. Customizing Configuration
Update the email settings in the script for alert notifications.
Modify IP ranges, targets, and other parameters as per your needs.
Usage Examples
Network Enumeration:

bash
Copy code
python network_security_analysis.py --enumerate "192.168.1.0/24"
SSH Brute-Force with Breach Check:

bash
Copy code
python network_security_analysis.py --bruteforce "192.168.1.10" --user "admin" --passwords "passwords.txt"
Port Monitoring:

bash
Copy code
python network_security_analysis.py --monitor "192.168.1.10" --interval 120
Contributions
Contributions are welcome! Please feel free to submit issues, feature requests, and pull requests.
