# 🛡️ Sentinel Port Scanner Pro

**Sentinel Port Scanner** is a multi-threaded, GUI-based network analysis tool designed for security auditing and network discovery. It features a modern dark-mode interface, banner grabbing capabilities, and an automated security risk assessment engine.

---

## 🚀 Features

### ⚡ Multi-Threaded Scanning

Leverages Python’s `ThreadPoolExecutor` to scan hundreds of ports simultaneously without freezing the UI.

### 🔍 Banner Grabbing

Attempts to retrieve service identification strings to identify running software and versions.

### 📊 Security Audit Report

Automatically calculates a **Security Score** based on:

* Open ports discovered
* Potentially risky services
* Known vulnerable software banners

### 💾 Export Options

Save scan results as:

* Professional **HTML Reports** with color-coded risk levels
* Plain **Text Reports**

### 🎯 Port Presets

Quick-select scanning profiles:

* **Common Ports:** `1–1024`
* **Web Ports:** `80, 443, 8080`
* **Full Scan:** `1–65535`

### 📡 Real-Time Monitor

Includes:

* Live scan status updates
* Progress tracking
* Real-time terminal-style output

---

## 🛠️ Installation

### Prerequisites

* Python **3.8+**
* `pip` (Python package manager)

### Install Dependencies

```bash
pip install PyQt6
```


---

## 🖥️ Usage

### Run the Application

```bash
python main.py
```

### Steps

1. **Enter Target**

   * IP Address: `192.168.1.1`
   * Hostname: `example.com`

2. **Select Port Range**

   * Choose a preset or manually define:

     * Start Port
     * End Port

3. **Start Scan**

   * Click **START SCAN**
   * Results appear in real-time

4. **Analyze Results**

   * Review:

     * Open ports
     * Service banners
     * Security score

5. **Save Report**

   * Export:

     * HTML summary
     * TXT report

---

## 🛡️ Security Assessment Logic

The scanner evaluates risk using:

### 🔓 Port Sensitivity

Known high-risk ports increase severity weighting, including:

* `21` → FTP
* `23` → Telnet
* `445` → SMB
* `3389` → RDP

### 🧬 Banner Matching

Identifies historically vulnerable software versions from retrieved banners.

Example detections:

* Outdated FTP servers
* Legacy SSH versions
* Vulnerable web server signatures

---

## ⚙️ Technical Highlights

* Built with **PyQt6**
* Uses **ThreadPoolExecutor** for concurrency
* Non-blocking GUI architecture
* Socket timeout handling
* HTML report generation
* Risk classification engine

---

## 📄 Example Output

```text
[OPEN] 22/tcp  - SSH
[BANNER] OpenSSH 7.2p2 Ubuntu

[OPEN] 80/tcp  - HTTP
[BANNER] Apache/2.4.18

Security Score: 72/100
Risk Level: MEDIUM
```

---

## 🔒 Disclaimer

> **For Educational and Authorized Testing Only**

Only use this tool on systems and networks you own or have explicit written permission to test.

Unauthorized port scanning may:

* Violate laws or policies
* Trigger intrusion detection systems
* Result in ISP or firewall blocks

The authors assume no responsibility for misuse or damage caused by this software.
