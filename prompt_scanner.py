import re
import hashlib
import getpass
import platform
from datetime import datetime
from pathlib import Path

LOG_FILE = "incident_log.txt"


def detect_sensitive_data(prompt):
    risk_score = 0
    detections = []

    # Detect internal IP addresses
    internal_ip_pattern = (
        r"\b(?:"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}"
        r")\b"
    )

    if re.search(internal_ip_pattern, prompt):
        detections.append("INTERNAL IP ADDRESS")
        risk_score += 25

    # Detect SSN: 123-45-6789
    ssn_pattern = r"\b\d{3}-\d{2}-\d{4}\b"

    if re.search(ssn_pattern, prompt):
        detections.append("SSN")
        risk_score += 60

    # Detect email address
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"

    if re.search(email_pattern, prompt):
        detections.append("EMAIL ADDRESS")
        risk_score += 10

    # Detect U.S. phone number
    phone_pattern = (
        r"(?<!\w)"
        r"(?:\+1[-.\s]?)?"
        r"(?:\(\d{3}\)|\d{3})[-.\s]?"
        r"\d{3}[-.\s]?\d{4}"
        r"(?!\w)"
    )

    if re.search(phone_pattern, prompt):
        detections.append("PHONE NUMBER")
        risk_score += 10

    # Detect passwords, secrets, tokens, or API-key assignments
    secret_pattern = (
        r"\b(password|passwd|pwd|secret|token|api[_-]?key)"
        r"\s*[:=]\s*\S+"
    )

    if re.search(secret_pattern, prompt, re.IGNORECASE):
        detections.append("PASSWORD OR SECRET")
        risk_score += 40

    # Detect internal server names
    server_pattern = (
        r"\b("
        r"DC\d{1,3}|"
        r"SQL-PROD-\d{1,3}|"
        r"[A-Z]{2,10}-FILESERVER-\d{1,3}"
        r")\b"
    )

    if re.search(server_pattern, prompt, re.IGNORECASE):
        detections.append("INTERNAL SERVER NAME")
        risk_score += 25

    # Detect internal company URLs
    internal_url_pattern = (
        r"\bhttps?://(?:"
        r"[A-Za-z0-9.-]+\.(?:local|internal|corp)|"
        r"(?:intranet|jira|confluence|gitlab|vpn)\.[A-Za-z0-9.-]+|"
        r"[A-Za-z0-9.-]*company[A-Za-z0-9.-]*"
        r")\b"
    )

    if re.search(internal_url_pattern, prompt, re.IGNORECASE):
        detections.append("INTERNAL COMPANY URL")
        risk_score += 25

    # Detect VPN information
    vpn_pattern = (
        r"\b("
        r"Cisco VPN|"
        r"Cisco AnyConnect|"
        r"Pulse Secure|"
        r"GlobalProtect|"
        r"FortiClient"
        r")\b"
    )

    if re.search(vpn_pattern, prompt, re.IGNORECASE):
        detections.append("VPN INFORMATION")
        risk_score += 25

    # Detect common API-key formats
    aws_access_key_pattern = r"\bAKIA[0-9A-Z]{16}\b"
    github_token_pattern = r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"
    openai_style_key_pattern = r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"

    if (
        re.search(aws_access_key_pattern, prompt)
        or re.search(github_token_pattern, prompt)
        or re.search(openai_style_key_pattern, prompt)
    ):
        detections.append("API KEY")
        risk_score += 70

    risk_score = min(risk_score, 100)

    return detections, risk_score


def get_risk_decision(risk_score):
    if risk_score <= 20:
        return "ALLOW", "SAFE"

    if risk_score <= 50:
        return "WARNING", "MEDIUM RISK"

    if risk_score <= 80:
        return "BLOCK", "HIGH RISK"

    return "BLOCK", "CRITICAL"


def save_incident(prompt, detections, risk_score, decision, risk_level):
    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    username = getpass.getuser()
    machine_name = platform.node()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write("AI Prompt Security Incident\n")
        log_file.write("Date and Time: " + timestamp + "\n")
        log_file.write("Username: " + username + "\n")
        log_file.write("Machine Name: " + machine_name + "\n")
        log_file.write("Prompt Hash: " + prompt_hash + "\n")
        log_file.write("Risk Score: " + str(risk_score) + "\n")
        log_file.write("Risk Level: " + risk_level + "\n")
        log_file.write("Decision: " + decision + "\n")
        log_file.write("Detected: " + ", ".join(detections) + "\n")
        log_file.write("-" * 45 + "\n")


def scan_prompt():
    print("\nEnter a prompt to scan.")
    print("Use dummy test data only. Do not enter real secrets.\n")

    prompt = input("Prompt: ").strip()

    if not prompt:
        print("\nNo prompt entered. Returning to the menu.")
        return

    detections, risk_score = detect_sensitive_data(prompt)
    decision, risk_level = get_risk_decision(risk_score)

    print("\n--- Scan Result ---")

    if len(detections) == 0:
        print("No sensitive data detected.")
    else:
        print("Detected:")

        for item in detections:
            print("- " + item)

    print("Risk Score:", risk_score)
    print("Decision:", decision)
    print("Risk Level:", risk_level)

    if decision == "WARNING":
        print("Reason: Review the prompt before submitting.")

    elif risk_level == "HIGH RISK":
        print("Reason: Sensitive information detected. Remove it before submitting.")

    elif risk_level == "CRITICAL":
        print("Reason: Critical sensitive information detected. Security alert required.")

    if decision == "BLOCK":
        save_incident(prompt, detections, risk_score, decision, risk_level)
        print("\nIncident saved in incident_log.txt")


def view_incident_log():
    log_path = Path(LOG_FILE)

    print("\n--- Incident Log ---")

    if not log_path.exists():
        print("No blocked incidents have been logged yet.")
        return

    print(log_path.read_text(encoding="utf-8"))


def view_security_summary():
    log_path = Path(LOG_FILE)

    print("\n" + "=" * 55)
    print("          PROMPTSHIELD DLP SECURITY SUMMARY")
    print("=" * 55)

    if not log_path.exists():
        print("\nNo blocked incidents have been logged yet.")
        return

    log_content = log_path.read_text(encoding="utf-8")

    total_incidents = log_content.count("AI Prompt Security Incident")
    critical_incidents = log_content.count("Risk Level: CRITICAL")
    high_risk_incidents = log_content.count("Risk Level: HIGH RISK")

    ssn_count = log_content.count("SSN")
    secret_count = log_content.count("PASSWORD OR SECRET")
    api_key_count = log_content.count("API KEY")
    internal_ip_count = log_content.count("INTERNAL IP ADDRESS")
    server_count = log_content.count("INTERNAL SERVER NAME")
    vpn_count = log_content.count("VPN INFORMATION")
    url_count = log_content.count("INTERNAL COMPANY URL")

    print("\nBlocked Incidents:", total_incidents)
    print("Critical Incidents:", critical_incidents)
    print("High Risk Incidents:", high_risk_incidents)

    print("\n--- Most Common Detected Data ---")
    print("SSN:", ssn_count)
    print("Passwords / Secrets:", secret_count)
    print("API Keys:", api_key_count)
    print("Internal IP Addresses:", internal_ip_count)
    print("Internal Server Names:", server_count)
    print("VPN Information:", vpn_count)
    print("Internal Company URLs:", url_count)

    print("\nPolicy Status: ACTIVE")
    print("Logging Status: ENABLED")
    print("Prompt Storage: HASH ONLY FOR BLOCKED INCIDENTS")


def main():
    print("=" * 55)
    print("        PromptShield DLP - Basic Demo")
    print("=" * 55)

    while True:
        print("\n1. Scan a prompt")
        print("2. View incident log")
        print("3. View security summary")
        print("4. Exit")

        choice = input("\nChoose an option (1, 2, 3, or 4): ").strip()

        if choice == "1":
            scan_prompt()

        elif choice == "2":
            view_incident_log()

        elif choice == "3":
            view_security_summary()

        elif choice == "4":
            print("\nPromptShield DLP closed.")
            break

        else:
            print("\nInvalid option. Please choose 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()