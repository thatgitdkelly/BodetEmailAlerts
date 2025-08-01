
# Copyright (C) 2025 Daniel Kelly
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.


import socket
import select
import datetime
import smtplib
from email.mime.text import MIMEText

# Multicast group and ports to listen on
MCAST_GRP = "239.192.55.3"
PORTS = [1681, 1680]

# SMTP settings (adjust these to your SMTP server and credentials)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "alerts@myemail.com"
SMTP_PASS = "APPPASSWORD"

# Global flag to enable/disable email alerts by default (can be overridden per event)
GLOBAL_EMAIL_ALERTS_ENABLED = True

# Packet prefix for check-in packets (REL) - Not sure of its purpose perhaps is a heartbeat/ checkin packet received every 10 secs.
CHECKIN_PREFIX = "52454c00"

# Define check-in settings
CHECKIN_SETTINGS = {
    "email_alert": False,       # typically, you might not want an email for every check-in
    "log_enabled": False,
    "email_subject": "Check-In Alert",
    "email_message": "A check-in event occurred from {addr} on port {port} at {timestamp}. Raw data: {raw}",
    "email_recipient": "alerts@myemail.com"
}

# Define button functions (physical button events).
# The key is the button code (extracted from indices 12-18).
# there are typically two packets for each button press. I will call them 'initiate' and 'complete' ending in 01 and 02
BUTTON_FUNCTIONS = {
    "010401": {
        "name": "Universal STOP Initiate (Physical Button 4)",
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "Button Alert: Universal STOP",
        "email_message": """The Universal STOP button press was detected.

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

Please take appropriate action.""",
        "email_recipient": "alerts@myemail.com"
    },
    "010402": {
        "name": "Universal STOP Complete (Physical Button 4)",
        "email_alert": True,
        "log_enabled": True,
        "email_subject": "Button Alert: Universal STOP",
        "email_message": """The Universal STOP button press was detected.

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

Please take appropriate action.""",
        "email_recipient": "alerts@myemail.com"
    },
    "010301": {
        "name": "Advance Bell Button Pressed (Physical Button 3)",
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "Button Alert: Advance School Button",
        "email_message": """Advance the School Bell Button press was detected.

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

Please take appropriate action.""",
        "email_recipient": "alerts@myemail.com"
    },
    "010302": {
        "name": "Advance Bell Button Pressed (Physical Button 3)",
        "email_alert": True,
        "log_enabled": True,
        "email_subject": "Button Alert: Advance School Button",
        "email_message": """Advance the School Bell Button press was detected.

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

Please take appropriate action.""",
        "email_recipient": "alerts@myemail.com"
    },
    "010201": {
        "name": "LOCK IN! PLEASE LOCK YOUR DOOR AND REMAIN UNTIL ALERTED (Physical Button 2)",
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "LOCK IN! PLEASE LOCK YOUR DOOR AND REMAIN UNTIL ALERTED BY THE ALL CLEAR ALERT",
        "email_message": "The Emergency Lockin has been initiated from {addr} on port {port} at {timestamp}. Raw data: {raw}",
        "email_message": """The Emergency Lockin has been initiated - PLEASE LOCK YOUR DOOR AND REMAIN UNTIL ALERTED BY THE ALL CLEAR ALERT.

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

Please take appropriate action.""",
        "email_recipient": "alerts@myemail.com"
    },
    "010202": {
        "name": "LOCK IN! PLEASE LOCK YOUR DOOR AND REMAIN UNTIL ALERTED (Physical Button 2)",
        "email_alert": True,
        "log_enabled": True,
        "email_subject": "LOCK IN! PLEASE LOCK YOUR DOOR AND REMAIN UNTIL ALERTED BY THE ALL CLEAR ALERT",
        "email_message": """The Emergency Lockin has been initiated - PLEASE LOCK YOUR DOOR AND REMAIN UNTIL ALERTED BY THE ALL CLEAR ALERT.

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

Please take appropriate action.""",
        "email_recipient": "alerts@myemail.com"
    },
    "010101": {
        "name": "ALL CLEAR! PLEASE CONTINUE WITH YOUR DAY (Physical Button 1)",
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "ALL CLEAR! PLEASE CONTINUE WITH YOUR DAY",
        "email_message": """ALL CLEAR! PLEASE CONTINUE WITH YOUR DAY

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

""",
        "email_recipient": "alerts@myemail.com"
    },
    "010102": {
        "name": "ALL CLEAR! PLEASE CONTINUE WITH YOUR DAY (Physical Button 1)",
        "email_alert": True,
        "log_enabled": True,
        "email_subject": "ALL CLEAR! PLEASE CONTINUE WITH YOUR DAY",
        "email_message": "The ALL CLEAR Alert has been initiated from {addr} on port {port} at {timestamp}. Raw data: {raw}",
        "email_message": """ALL CLEAR! PLEASE CONTINUE WITH YOUR DAY

Details:
- Source IP: {addr}
- Port: {port}
- Timestamp: {timestamp}
- Raw Data: {raw}

""",
        "email_recipient": "alerts@myemail.com"
    },
    # Add additional button mappings for buttons as needed.
}

# Define melody patterns for up to 10 melodies plus a STOP command.
# Each entry includes matching criteria plus extra fields for alerts and logging.
# Each melody broadcast will include an integer at the 16th index to define what melody is to be played
MELODY_PATTERNS = {
    "Melody 1": {
        "prefix": "4d454c0",
        "length": 40,
        "fields": {16: "01"},
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "Melody 1 Detected",
        "email_message": "Melody 1 was detected from {addr} on port {port} at {timestamp}. Raw data: {raw}",
        "email_recipient": "melody1@example.com"
    },
    "Melody 2": {
        "prefix": "4d454c0",
        "length": 40,
        "fields": {16: "02"},
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "Melody 2 Detected",
        "email_message": "Melody 2 was detected from {addr} on port {port} at {timestamp}. Raw data: {raw}",
        "email_recipient": "melody2@example.com"
    },
    "Melody 3": {
        "prefix": "4d454c0",
        "length": 40,
        "fields": {16: "03"},
        "email_alert": False,
        "log_enabled": True,
        "email_subject": "Melody 3 Detected",
        "email_message": "Melody 3 was detected from {addr} on port {port} at {timestamp}. Raw data: {raw}",
        "email_recipient": "melody3@example.com"
    },
    # ... add melodies 4 through 10 similarly ...
    "STOP": {
        "prefix": "4d454c0",
        "length": 52,
        "fields": {16: "ff"},
        "email_alert": True,
        "log_enabled": True,
        "email_subject": "STOP Command Detected",
        "email_message": "A STOP command was detected from {addr} on port {port} at {timestamp}. Raw data: {raw}",
        "email_recipient": "alerts@myemail.com"
    },
}

# Function to send an email alert using smtplib.
def send_email(subject, body, recipient):
    if not GLOBAL_EMAIL_ALERTS_ENABLED:
        return
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = recipient

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"Email sending failed: {e}")

# Function to log results to a file.
def log_to_file(message):
    with open("melody_results.log", "a") as f:
        f.write(message + "\n")

def create_multicast_socket(port):
    """Creates and returns a multicast UDP socket bound to the given port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    mreq = socket.inet_aton(MCAST_GRP) + socket.inet_aton("0.0.0.0")
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock

def detect_melody(hex_data):
    """
    Checks if hex_data matches any known melody pattern.
    Returns the melody name if matched, otherwise None.
    """
    for melody_name, criteria in MELODY_PATTERNS.items():
        if len(hex_data) == criteria["length"] and hex_data.startswith(criteria["prefix"]):
            valid = True
            for pos, expected in criteria.get("fields", {}).items():
                if hex_data[pos:pos+2] != expected:
                    valid = False
                    break
            if valid:
                return melody_name
    return None

# Create sockets for each port.
sockets = [create_multicast_socket(port) for port in PORTS]

print(f"Listening for UDP multicast packets on {MCAST_GRP} on ports {PORTS}...\n")

# Variable to hold the last check-in packet for deduplication.
last_checkin_packet = None

while True:
    readable, _, _ = select.select(sockets, [], [])
    for sock in readable:
        data, addr = sock.recvfrom(1024)
        hex_data = data.hex()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        local_port = sock.getsockname()[1]

        # Process check-in packets (prefix CHECKIN_PREFIX).
        if hex_data.startswith(CHECKIN_PREFIX):
            # Deduplicate identical check-in packets.
            if hex_data == last_checkin_packet:
                continue
            last_checkin_packet = hex_data

            if len(hex_data) >= 32:
                # Extract the incremental counter (2 bytes at indices 12-16).
                counter_hex = hex_data[12:16]
                counter_int = int(counter_hex, 16)
                output = f"[{timestamp}] [Port {local_port}] CHECK-IN from {addr}: Counter = {counter_hex} (int: {counter_int}) | Raw: {hex_data}"
                print(output)
                # Check-in events typically are not emailed by default (as per settings)
                if CHECKIN_SETTINGS["log_enabled"]:
                    log_to_file(output)
                if CHECKIN_SETTINGS["email_alert"]:
                    subject = CHECKIN_SETTINGS["email_subject"]
                    body = CHECKIN_SETTINGS["email_message"].format(addr=addr, port=local_port, timestamp=timestamp, raw=hex_data)
                    send_email(subject, body, CHECKIN_SETTINGS["email_recipient"])
            else:
                output = f"[{timestamp}] [Port {local_port}] CHECK-IN from {addr}: Packet too short | Raw: {hex_data}"
                print(output)
                log_to_file(output)

        # Process button events (packets starting with "424f55").
        elif hex_data.startswith("424f55"):
            # Extract button code from indices 12 to 18.
            button_code = hex_data[12:18]
            btn = BUTTON_FUNCTIONS.get(button_code, {"name": "Unknown Button Event", "email_alert": False, "log_enabled": True,
                                                      "email_subject": "Button Alert: Unknown",
                                                      "email_message": "An unknown button event occurred from {addr} on port {port} at {timestamp}. Raw: {raw}",
                                                      "email_recipient": "unknown@example.com"})
            output = f"[{timestamp}] [Port {local_port}] BUTTON EVENT from {addr}: Code = {button_code} -> {btn['name']} | Raw: {hex_data}"
            print(output)
            if btn["log_enabled"]:
                log_to_file(output)
            if btn["email_alert"]:
                subject = btn["email_subject"]
                body = btn["email_message"].format(addr=addr, port=local_port, timestamp=timestamp, raw=hex_data)
                send_email(subject, body, btn["email_recipient"])

        # Process melody events (packets starting with "4d454c00").
        elif hex_data.startswith("4d454c00"):
            melody_name = detect_melody(hex_data)
            if melody_name:
                # Retrieve the settings for the detected melody.
                melody_settings = MELODY_PATTERNS[melody_name]
                output = f"[{timestamp}] [Port {local_port}] {melody_name} detected from {addr}: Raw: {hex_data}"
                print(output)
                if melody_settings.get("log_enabled", True):
                    log_to_file(output)
                if melody_settings.get("email_alert", False):
                    subject = melody_settings.get("email_subject", f"{melody_name} Alert")
                    body = melody_settings.get("email_message", f"{melody_name} was detected from {addr} on port {local_port} at {timestamp}. Raw: {hex_data}")
                    recipient = melody_settings.get("email_recipient", SMTP_USER)
                    send_email(subject, body.format(addr=addr, port=local_port, timestamp=timestamp, raw=hex_data), recipient)
            else:
                output = f"[{timestamp}] [Port {local_port}] Unknown MELODY packet from {addr}: Raw: {hex_data}"
                print(output)
                log_to_file(output)

        # Process any other packets.
        else:
            output = f"[{timestamp}] [Port {local_port}] Packet from {addr}: {hex_data}"
            print(output)
            log_to_file(output)
