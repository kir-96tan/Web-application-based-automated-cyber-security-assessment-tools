# Web-Application-Based Automated Cyber Security Assessment Tools

A Python Flask-based web application that integrates essential cybersecurity tools like Nmap, Metasploit, and Wireshark to automate vulnerability scanning, reporting, and risk mitigation in web systems.

## 🔒 Project Overview

This project aims to simplify and automate the process of identifying vulnerabilities in web applications. Built using the Flask framework, the application provides a web interface for launching security scans and collecting results, making it easier for users to assess the security posture of their systems without deep command-line expertise.

## 🧰 Tools & Technologies

- **Flask** (Python Web Framework)
- **Nmap** (Network Mapper)
- **Metasploit Framework** (Penetration Testing)
- **Wireshark** (Network Packet Analysis)
- **HTML/CSS/JavaScript** (Frontend UI)
- **Bootstrap** (Responsive Design)
- **MySQL** (Data storage for scan reports and logs)

## 🛡️ Features

- 🔍 Perform **network vulnerability scans** using Nmap.
- 💥 Interface with **Metasploit** to simulate attack scenarios.
- 📡 Capture and analyze packets using **Wireshark**.
- 📊 Generate automated scan reports with findings and recommendations.
- 🧠 User-friendly web dashboard for inputting targets and reviewing results.
- 🔐 Basic authentication to protect the application.

## 🖥️ Screenshots

> *[Insert screenshots of the dashboard, scan input, and results pages]*

## 🚀 How to Run the Project Locally

### Prerequisites
- Python 3.7+
- Flask
- Nmap installed on system
- Metasploit Framework installed
- Wireshark (optional but recommended)

### Setup Instructions

```bash
git clone https://github.com/<your-username>/Web-Application-Based-Automated-Cyber-Security-Assessment-Tools.git
cd Web-Application-Based-Automated-Cyber-Security-Assessment-Tools
pip install -r requirements.txt
python app.py

├── app.py
├── templates/
│   └── index.html
│   └── results.html
├── static/
│   └── styles.css
├── modules/
│   └── nmap_scan.py
│   └── metasploit.py
│   └── wireshark_capture.py
├── reports/
│   └── scan_report_<timestamp>.txt
└── requirements.txt


