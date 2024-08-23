import scapy.all as scapy
import re
import logging
import smtplib
from email.mime.text import MIMEText
from sklearn.ensemble import IsolationForest
import numpy as np
import os
from flask import Flask, render_template, jsonify, request
import requests
import ssl
from threading import Thread
from collections import defaultdict
import time
import dotenv
from pathlib import Path
import asyncio
import aiohttp

# Load environment variables
dotenv.load_dotenv()
THREAT_INTELLIGENCE_API_KEY = os.getenv('THREAT_INTELLIGENCE_API_KEY')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SENDER_EMAIL = os.getenv('SENDER_EMAIL')
RECIPIENT_EMAIL = os.getenv('RECIPIENT_EMAIL')

# Configure logging
logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')
alert_threshold = 0.6

# Attack signatures
attack_signatures = [
    re.compile(r'bad_payload_signature'),
    re.compile(r'sql_injection_attempt'),
    re.compile(r'XSS_attack_detected')
]

# Anomaly detection model setup with real training data
# Assuming 'real_training_data.npy' is a pre-collected dataset of normal network traffic
training_data_path = Path('real_training_data.npy')
if training_data_path.exists():
    training_data = np.load(training_data_path)
else:
    # Fallback in case the dataset is missing
    training_data = np.random.rand(1000, 3)

anomaly_model = IsolationForest(contamination=0.05)
anomaly_model.fit(training_data)

# Threat intelligence service (e.g., abuseipdb.com) for known malicious IPs
threat_intelligence_url = f'https://api.abuseipdb.com/api/v2/check'
headers = {
    'Key': THREAT_INTELLIGENCE_API_KEY,
    'Accept': 'application/json'
}

# Whitelist for IPs that should never be blocked
whitelisted_ips = {'192.168.1.1', '127.0.0.1'}

# IP reputation score dictionary
ip_reputation_scores = defaultdict(lambda: 0)

# Asynchronous email alert function with TLS encryption
async def send_email_alert(subject, message):
    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECIPIENT_EMAIL
    context = ssl.create_default_context()

    try:
        with smtplib.SMTP_SSL('smtp.example.com', 465, context=context) as server:
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        logging.info("Email alert sent successfully")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

# Function to block IP address
def block_ip(ip):
    if ip in whitelisted_ips:
        logging.info(f"Attempt to block whitelisted IP: {ip} was ignored.")
        return
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    logging.info(f"Blocked IP: {ip}")

# Asynchronous function to query threat intelligence for known malicious IPs
async def check_ip_reputation(ip):
    if ip in whitelisted_ips:
        return

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(threat_intelligence_url, headers=headers, params={'ipAddress': ip, 'maxAgeInDays': '90'}) as response:
                data = await response.json()
                if 'data' in data:
                    ip_reputation_scores[ip] = data['data']['abuseConfidenceScore']
                    if ip_reputation_scores[ip] > 50:  # Threshold for blocking based on reputation
                        logging.warning(f"IP {ip} blocked based on reputation score: {ip_reputation_scores[ip]}")
                        block_ip(ip)
        except Exception as e:
            logging.error(f"Failed to check IP reputation: {e}")

# Function to detect anomalies in network traffic
def detect_anomalies(packet):
    stats = np.array([[packet.len, packet.time, packet.ttl]])
    score = anomaly_model.decision_function(stats)[0]
    return score < alert_threshold

# Function to handle packet analysis
def monitor_traffic(packet):
    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load.decode(errors='ignore')
        ip_src = packet[scapy.IP].src

        # Asynchronous IP reputation check
        asyncio.run(check_ip_reputation(ip_src))

        # Signature-based detection
        for signature in attack_signatures:
            if signature.search(payload):
                logging.warning(f"Signature match: {signature.pattern} from {ip_src}")
                asyncio.run(send_email_alert("Signature Match Detected", f"Match: {signature.pattern} from {ip_src}"))
                block_ip(ip_src)
                return

        # Anomaly-based detection
        if detect_anomalies(packet):
            logging.warning(f"Anomaly detected from {ip_src}")
            asyncio.run(send_email_alert("Anomaly Detected", f"Anomaly detected from {ip_src}"))
            block_ip(ip_src)

# Web interface for monitoring and managing the IDS
app = Flask(__name__)

@app.route('/')
def index():
    with open('ids.log', 'r') as f:
        logs = f.read().splitlines()
    return render_template('index.html', logs=logs)

@app.route('/api/logs')
def get_logs():
    with open('ids.log', 'r') as f:
        logs = f.read().splitlines()
    return jsonify(logs)

@app.route('/api/whitelist', methods=['POST'])
def add_whitelist():
    ip = request.form['ip']
    whitelisted_ips.add(ip)
    return jsonify({"message": f"IP {ip} added to whitelist"}), 200

@app.route('/api/blocklist', methods=['POST'])
def block_ip_route():
    ip = request.form['ip']
    block_ip(ip)
    return jsonify({"message": f"IP {ip} has been blocked"}), 200

@app.route('/dashboard')
def dashboard():
    logs_count = len(open('ids.log').readlines())
    unique_ips = len(set(ip_reputation_scores.keys()))
    blocked_ips = len([ip for ip in ip_reputation_scores if ip_reputation_scores[ip] > 50])
    return render_template('dashboard.html', logs_count=logs_count, unique_ips=unique_ips, blocked_ips=blocked_ips)

if __name__ == '__main__':
    # Start network monitoring and web interface
    scapy_thread = Thread(target=lambda: scapy.sniff(prn=monitor_traffic, store=False))
    scapy_thread.daemon = True
    scapy_thread.start()

    # Run Flask app
    app.run(host='0.0.0.0', port=8080)
