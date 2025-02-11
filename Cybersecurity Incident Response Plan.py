import logging
import os
import time
import json
import smtplib
from datetime import datetime

# Configure Logging
logging.basicConfig(
    filename="incident_response.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Incident Classification Thresholds
THRESHOLDS = {
    "low": 1,
    "medium": 5,
    "high": 10
}

# Sample Threat Indicators (Can be expanded dynamically)
THREAT_INDICATORS = [
    "failed login", "unauthorized access", "malware detected", "DDoS attack", "phishing attempt"
]

def detect_threat(log_file="system_logs.txt"):
    """Scans logs for potential threats."""
    incidents = []
    try:
        with open(log_file, "r") as file:
            for line in file:
                for indicator in THREAT_INDICATORS:
                    if indicator.lower() in line.lower():
                        logging.warning(f"Threat detected: {line.strip()}")
                        incidents.append(line.strip())
    except FileNotFoundError:
        logging.error("Log file not found.")
    return incidents


def classify_incident(incidents):
    """Classifies incident severity based on occurrences."""
    count = len(incidents)
    if count >= THRESHOLDS["high"]:
        return "High"
    elif count >= THRESHOLDS["medium"]:
        return "Medium"
    elif count >= THRESHOLDS["low"]:
        return "Low"
    return "None"


def respond_to_incident(incident_level):
    """Executes appropriate response actions based on severity."""
    response_actions = {
        "Low": "Monitor logs and alert IT team.",
        "Medium": "Isolate affected systems and notify security team.",
        "High": "Activate incident response team, isolate networks, and escalate."
    }
    
    if incident_level in response_actions:
        logging.info(f"Response action: {response_actions[incident_level]}")
        print(f"Response Action: {response_actions[incident_level]}")
    else:
        logging.info("No action needed.")


def send_alert(incident_level, incidents):
    """Sends an alert email for high-severity incidents."""
    if incident_level == "High":
        sender_email = "security@company.com"
        receiver_email = "incident-response@company.com"
        subject = "ALERT: High Severity Cybersecurity Incident Detected"
        message = f"""
        Subject: {subject}
        
        High severity security incident detected.
        
        Detected Threats:
        {json.dumps(incidents, indent=2)}
        
        Immediate response required.
        """
        try:
            with smtplib.SMTP("smtp.example.com") as server:
                server.sendmail(sender_email, receiver_email, message)
            logging.info("Alert email sent successfully.")
        except Exception as e:
            logging.error(f"Failed to send alert email: {e}")


def main():
    """Main function to execute the incident response process."""
    print("Scanning for threats...")
    incidents = detect_threat()
    incident_level = classify_incident(incidents)
    print(f"Incident Severity: {incident_level}")
    respond_to_incident(incident_level)
    send_alert(incident_level, incidents)

if __name__ == "__main__":
    main()
