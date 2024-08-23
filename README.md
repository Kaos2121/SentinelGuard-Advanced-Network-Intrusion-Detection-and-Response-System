
---

# SentinelGuard: Advanced Network Intrusion Detection and Response System

## Overview

**SentinelGuard** is an advanced Intrusion Detection and Response System (IDRS) designed to monitor network traffic, detect malicious activities, and respond in real-time to potential threats. Leveraging a combination of signature-based detection, anomaly detection using machine learning, and integration with external threat intelligence services, SentinelGuard provides a robust and comprehensive security solution. It also includes a user-friendly web-based dashboard for monitoring, logging, and managing the system.

## Features

- **Real-Time Network Monitoring**: Continuously monitors network traffic, analyzing each packet for potential threats.
- **Signature-Based Detection**: Identifies known attack patterns using predefined signatures.
- **Anomaly Detection**: Utilizes a machine learning model (Isolation Forest) to detect unusual behavior that deviates from the norm.
- **Threat Intelligence Integration**: Automatically queries external threat intelligence services to assess the reputation of IP addresses.
- **Automated Response**: Automatically blocks malicious IP addresses by updating firewall rules.
- **IP Whitelisting**: Prevents certain IP addresses from being blocked, even if they trigger an alert.
- **Encrypted Communication**: Ensures all email alerts are sent securely using TLS encryption.
- **Comprehensive Web Dashboard**: Offers real-time monitoring, log access, and management features via a Flask-based web interface.

## Installation

### Prerequisites

- Python 3.7+
- `pip` package manager
- Basic knowledge of network security and firewall management

### Dependencies

Install the required Python packages:

```bash
pip install scapy Flask sklearn requests
```

### Setting Up SentinelGuard

1. **Clone the Repository**

   Clone the repository to your local machine:

   ```bash
   git clone https://github.com/yourusername/sentinelguard.git
   cd sentinelguard
   ```

2. **Configure Email Alerts**

   Open the script `advanced_ids.py` and configure the email settings for alerting:

   ```python
   sender = 'your_email@example.com'
   recipient = 'alert_recipient@example.com'
   smtp_server = 'smtp.example.com'
   smtp_port = 465
   smtp_password = 'your_email_password'
   ```

3. **Obtain a Threat Intelligence API Key**

   Sign up for a threat intelligence service (e.g., AbuseIPDB) and obtain an API key. Replace the placeholder in the script:

   ```python
   THREAT_INTELLIGENCE_API_KEY = 'your_threat_intelligence_api_key'
   ```

4. **Run SentinelGuard**

   Start the SentinelGuard IDS by running the script:

   ```bash
   python advanced_ids.py
   ```

   The system will begin monitoring network traffic and start the web interface on `http://0.0.0.0:8080`.

## Usage

### Real-Time Monitoring

SentinelGuard monitors network traffic in real-time using `scapy` to sniff packets. It performs the following checks on each packet:

1. **Signature-Based Detection**: Matches the packet payload against known attack signatures.
2. **Anomaly Detection**: Uses an Isolation Forest model to identify deviations from normal traffic patterns.
3. **Threat Intelligence**: Checks the source IP address against an external threat intelligence service to determine if it is a known malicious IP.

### Automated Response

When a threat is detected, SentinelGuard automatically takes the following actions:

- Logs the incident with a timestamp and details in `ids.log`.
- Sends an email alert to the specified recipient.
- Blocks the source IP by adding a rule to the firewall.

### Web Dashboard

Access the web dashboard at `http://your-server-ip:8080` to:

- View real-time logs of detected threats.
- Add IP addresses to the whitelist to prevent them from being blocked.
- Manually block specific IP addresses.
- Access a comprehensive dashboard that provides statistics such as the number of detected threats, blocked IPs, and more.

### IP Whitelisting

To prevent important IP addresses from being blocked, you can add them to the whitelist via the web interface or by editing the `whitelisted_ips` set directly in the script.

### Log Management

Logs are automatically stored in `ids.log`. The web interface allows you to view these logs and filter them based on time, type of threat, and more.

## Customization

### Adding New Attack Signatures

To enhance the signature-based detection, you can add new regular expressions to the `attack_signatures` list in the script. For example:

```python
attack_signatures.append(re.compile(r'new_attack_signature'))
```

### Adjusting Anomaly Detection

The threshold for anomaly detection is set with `alert_threshold`. You can adjust this value to make the system more or less sensitive to anomalies:

```python
alert_threshold = 0.6  # Lower value = more sensitive, Higher value = less sensitive
```

### Expanding the Dashboard

The web interface can be expanded with additional features or customized to meet specific needs. The Flask app is designed to be easily extensible.

## Security Considerations

- Ensure that only trusted personnel have access to the web interface.
- Regularly update the threat intelligence API key and ensure the service you use is reliable.
- Consider integrating additional security measures such as multi-factor authentication for accessing the web dashboard.

## Troubleshooting

- **No Alerts**: Ensure that the network interface is correctly set up and that SentinelGuard is running with the necessary privileges to sniff traffic.
- **Email Alerts Not Working**: Verify the SMTP settings and ensure the email server allows external connections.
- **Web Interface Not Accessible**: Check that the Flask server is running and that there are no firewall rules blocking access to port 8080.

## Future Enhancements

- **Integration with SIEM Systems**: Allow SentinelGuard to feed data into Security Information and Event Management (SIEM) platforms.
- **Machine Learning Model Retraining**: Implement periodic retraining of the anomaly detection model with new data to keep it up-to-date.
- **DDoS Detection**: Add advanced rate limiting and DDoS detection mechanisms.

## License

SentinelGuard is licensed under the MIT License. See the `LICENSE.md` file for more details.

## Disclaimer

This software is intended for educational purposes and as a starting point for developing advanced network security systems. It is not a replacement for a professionally managed intrusion detection system. Use this tool at your own risk and ensure it is deployed in environments where you have permission to monitor and manage network traffic.

---
