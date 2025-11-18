Project 1

[Security audit of sample system.py](https://github.com/user-attachments/files/23613793/Security.audit.of.sample.system.py)
import os
import platform
import socket

def system_info():
    print("=== System Information ===")
    print(f"OS: {platform.system()} {platform.release()}")
    print(f"Hostname: {socket.gethostname()}")
    print(f"User: {os.getlogin()}")
    print(f"Working Directory: {os.getcwd()}")
    print("==========================\n")

def check_critical_files():
    print("=== Checking Critical Files ===")
    files_to_check = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]
    for file in files_to_check:
        if os.path.exists(file):
            print(f"[OK] {file} exists.")
        else:
            print(f"[WARNING] {file} not found!")
    print("===============================\n")

def main():
    system_info()
    check_critical_files()
    print("Cybersecurity audit completed successfully.")

if __name__ == "__main__":
    main()
Uploading Security audit of sample system.py…]()



Project 2


[Analyzing and mitigating network vulnerablities.py](https://github.com/user-attachments/files/23613797/Analyzing.and.mitigating.network.vulnerablities.py)
import socket

def scan_ports(host="127.0.0.1", ports=[22, 80, 443]):
    print(f"Scanning ports on {host}...\n")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"[OPEN] Port {port} is open. Consider firewall rules or monitoring.")
        else:
            print(f"[CLOSED] Port {port} is closed.")
        sock.close()
    print("\nNetwork vulnerability scan completed.")

if __name__ == "__main__":
    scan_ports()



Project 3



[Investigating Simulated Security Breaches and Creating Incident Reports.py](https://github.com/user-attachments/files/23613814/Investigating.Simulated.Security.Breaches.and.Creating.Incident.Reports.py)
import re
import os

def create_default_logs(log_file):
    sample_logs = """2025-11-18 09:00:01 - User admin - Failed login
2025-11-18 09:05:12 - User guest - Successful login
2025-11-18 09:10:45 - User admin - Unauthorized access to /etc/shadow
2025-11-18 09:15:30 - User root - Successful login
"""
    with open(log_file, "w") as f:
        f.write(sample_logs)
    print(f"[INFO] '{log_file}' not found. A default one has been created.\n")

def analyze_logs(log_file="simulated_logs.txt"):
    # Create the log file if missing
    if not os.path.exists(log_file):
        create_default_logs(log_file)

    print("Analyzing Logs for Suspicious Activity")
    suspicious_patterns = [r"Failed login", r"Unauthorized access"]

    with open(log_file, "r") as f:
        logs = f.readlines()
    
    incidents = []
    for line in logs:
        for pattern in suspicious_patterns:
            if re.search(pattern, line):
                incidents.append(line.strip())
    
    if incidents:
        print(f"Found {len(incidents)} suspicious events:")
        for i, incident in enumerate(incidents, 1):
            print(f"{i}. {incident}")
    else:
        print("No suspicious activity found.")

    print("\nGenerating incident report...")
    with open("incident_report.md", "w") as report:
        report.write("# Incident Report\n\n")
        if incidents:
            for i, incident in enumerate(incidents, 1):
                report.write(f"{i}. {incident}\n")
        else:
            report.write("No suspicious activity detected.\n")
    print("Incident report saved as incident_report.md")

if __name__ == "__main__":
    analyze_logs()
    input("\nPress ENTER to exit...")




Project 4



[Setting up Secure Networks and best practises.py](https://github.com/user-attachments/files/23613845/Setting.up.Secure.Networks.and.best.practises.py)
def network_best_practices():
    print("Network Security Best Practices")
    best_practices = [
        "1. Use strong, unique passwords for all devices and accounts.",
        "2. Keep software and firmware up-to-date.",
        "3. Enable firewalls and configure router settings securely.",
        "4. Use VPNs when accessing public networks.",
        "5. Segment networks to limit access to critical resources.",
        "6. Monitor network traffic for unusual activity.",
        "7. Implement least privilege access policies."
    ]
    for tip in best_practices:
        print(tip)

def main():
    network_best_practices()
    print("Secure network setup guide completed.")

if __name__ == "__main__":
    main()








