# Enhanced HTTPS/TLS Traffic Analysis using Blockchain and Machine Learning

## Overview
This project focuses on analyzing HTTPS/TLS encrypted traffic by integrating **Wireshark-based packet capture**, **blockchain-secured logging**, and **machine learning for anomaly detection**. The goal is to enhance visibility into encrypted communications while ensuring data integrity and threat detection.

## Key Features
- **HTTPS/TLS Traffic Analysis**: Capture and decrypt TLS handshakes using Wireshark with `SSLKEYLOGFILE`.
- **Blockchain Logging**: Immutable recording of session metadata (IPs, TLS versions, cipher suites) via a lightweight Python blockchain.
- **Anomaly Detection**: ML models (Isolation Forest/One-Class SVM) to identify malicious patterns in encrypted traffic.
- **Integration**: Unified tool for traffic inspection, blockchain logs, and visualization of anomalies.

## Methodology
1. **Traffic Capture**: Filter TLS packets and decrypt sessions for analysis.
2. **Blockchain Integration**: Log metadata to a tamper-proof private blockchain.
3. **ML Pipeline**: Extract features (packet size, session duration) and train unsupervised models.
4. **Visualization**: CLI/GUI tool to display logs, anomalies, and replay packets.

## Team
- N Ragavenderan (`1RV22CS122`)
- Saara Unnathi R (`1RV22CS167`)
- Rakshitha K (`1RV23CS414`)  
**Guide**: Prof. Deepika Dash, CSE, RVCE.

## Methodology
1. Traffic Capture & Decryption  
2. Blockchain Log System  
3. ML Model Training  
4. Tool Integration & Testing  

## Technologies
- **Tools**: Wireshark, Python
- **Cryptography**: RSA (key exchange), AES (session encryption)
- **ML**: Scikit-learn (Isolation Forest, SVM)
- **Blockchain**: Custom Python implementation

---
**Note**: Project developed for **Cryptography and Network Security** (6th Sem, RVCE).  
For details, refer to the project report or contact the team.
