import sys #Provides access to system-specific parameters and functions
import socket #Enables low-level network communications, allowing you to create TCP/UDP connections, servers, and clients
from datetime import datetime
# Import necessary UI components from PyQt6 for the graphical interface
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QLineEdit, QPushButton, QTextEdit,
                             QLabel, QProgressBar, QFrame, QFileDialog, QComboBox)
# Import core constants like Alignment and Threading support
from PyQt6.QtCore import Qt, QThread

# Importing custom logic for the actual scanning work and predefined suggestions/port lists
# These are expected to be in a separate file named scanner_worker.py
from scanner_worker import ScannerWorker, SUGGESTIONS

class CyberToolGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        # Retrieve the local IP of the machine running the script for display
        self.local_ip = self.get_local_ip()
        # Initialize placeholders for the background thread and worker object
        self.thread = None
        self.worker = None
        # Build the user interface
        self.initUI()

    def initUI(self):
        """Sets up the window properties, styles, and layout components."""
        self.setWindowTitle("Sentinel Port Scanner Pro + Banner Grabbing")
        self.setMinimumSize(850, 900)
        
        # Central widget acts as the container for all other UI elements
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Global stylesheet (CSS-like) to give the app a 'Dark Mode' hacker aesthetic
        self.setStyleSheet("""
            QMainWindow { background-color: #0b0e14; }
            QLabel { color: #8f9aaa; font-family: 'Segoe UI'; font-size: 13px; }
            QLineEdit { 
                background-color: #161b22; color: #58a6ff; border: 1px solid #30363d; 
                padding: 8px; border-radius: 6px; 
            }
            QComboBox { 
                background-color: #161b22; color: #58a6ff; border: 1px solid #30363d; 
                padding: 8px; border-radius: 6px; 
            }
            QComboBox QAbstractItemView {
                background-color: #161b22;
                color: #58a6ff;
                selection-background-color: #238636;
            }
            QPushButton { 
                border-radius: 6px; padding: 10px; font-weight: bold; border: none;
                font-family: 'Segoe UI'; color: white;
            }
            QTextEdit {
                background-color: #0d1117; color: #d1d5da; border: 1px solid #30363d;
                font-family: 'Consolas', monospace; font-size: 12px;
            }
        """)

        # --- Header Section ---
        title = QLabel("NETWORK ANALYZER")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #238636; margin-top: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # Displays the user's current local IP address
        self.ip_label = QLabel(f"Your IP: {self.local_ip}")
        self.ip_label.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        self.ip_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.ip_label)

        # Activity Monitor shows real-time status updates (e.g., "Scanning port 80...")
        self.status_monitor = QLabel("Ready to scan...")
        self.status_monitor.setStyleSheet("color: #d1d5da; font-style: italic; font-family: monospace;")
        self.status_monitor.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_monitor)

        # --- Target Input Section ---
        input_frame = QFrame()
        input_layout = QVBoxLayout(input_frame)
        
        # Input field for the target URL or IP address
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter Target IP or Hostname (e.g., google.com)...")
        
        # Layout for port range selection and presets
        preset_layout = QHBoxLayout()
        self.preset_combo = QComboBox()
        self.preset_combo.addItems(["Common (1-1024)", "Web (80, 443, 8080)", "Full (1-65535)"])
        # Connect dropdown change to the apply_preset function
        self.preset_combo.currentIndexChanged.connect(self.apply_preset)
        
        # Input fields for manual start and end port numbers
        self.start_port = QLineEdit("1")
        self.end_port = QLineEdit("1024")
        
        preset_layout.addWidget(QLabel("Ports:"))
        preset_layout.addWidget(self.preset_combo)
        preset_layout.addWidget(self.start_port)
        preset_layout.addWidget(self.end_port)

        input_layout.addWidget(QLabel("Target IP Address:"))
        input_layout.addWidget(self.target_input)
        input_layout.addLayout(preset_layout)
        layout.addWidget(input_frame)

        # --- Control Buttons Section ---
        btn_layout = QHBoxLayout()
        
        # Button to trigger the start or stop of a scan
        self.scan_btn = QPushButton("START SCAN")
        self.scan_btn.setStyleSheet("background-color: #238636;")
        self.scan_btn.clicked.connect(self.toggle_scan)
        
        # Button to wipe the text output area
        self.clear_btn = QPushButton("CLEAR SCREEN")
        self.clear_btn.setStyleSheet("background-color: #444c56;")
        self.clear_btn.clicked.connect(lambda: self.output_area.clear())
        
        # Button to export the results to a .txt file
        self.save_btn = QPushButton("SAVE REPORT")
        self.save_btn.setStyleSheet("background-color: #1f6feb;")
        self.save_btn.clicked.connect(self.save_log)
        
        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.clear_btn)
        btn_layout.addWidget(self.save_btn)
        layout.addLayout(btn_layout)

        # --- Progress and Output ---
        # Visual progress bar for the scanning process
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar { border: 1px solid #30363d; border-radius: 4px; text-align: center; color: white; background: #0d1117; height: 15px; }
            QProgressBar::chunk { background-color: #238636; }
        """)
        layout.addWidget(self.progress_bar)

        # Large read-only text area to display found open ports and banners
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

    def apply_preset(self, index):
        """Sets the start and end port inputs based on a selected dropdown/button index."""
        # Dictionary mapping index to specific port ranges (Common, Web, All)
        ranges = {0: ("1", "1024"), 1: ("80", "8080"), 2: ("1", "65535")}
        if index in ranges:
            # Update the UI text fields with the selected range
            self.start_port.setText(ranges[index][0])
            self.end_port.setText(ranges[index][1])

    def get_local_ip(self):
        """Attempts to find the machine's local IP address by creating a dummy socket."""
        try:
            # Create a UDP socket (DGRAM)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Connect to a public DNS (8.8.8.8) to see which local interface is used
                # No data is actually sent
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            # Fallback to localhost if no network connection is available
            return "127.0.0.1"

    def toggle_scan(self):
        """Switches between starting and stopping the scan based on current button state."""
        if self.scan_btn.text() == "START SCAN":
            self.start_scanning()
        else:
            self.stop_scanning()

    def start_scanning(self):
        """Initializes and launches the background scanning thread."""
        # Get and clean the target input (IP or Domain)
        target = self.target_input.text().strip()
        if not target:
            self.output_area.append("[!] Error: Target is required.")
            return

        # Update UI button to 'Stop' mode with a red color
        self.scan_btn.setText("STOP SCAN")
        self.scan_btn.setStyleSheet("background-color: #da3633;")
        self.output_area.append(f"\n--- Scan Started: {datetime.now().strftime('%H:%M:%S')} ---")
        
        # Setup multi-threading to keep the UI responsive during the scan
        self.thread = QThread()
        self.worker = ScannerWorker()
        self.worker.moveToThread(self.thread)
        
        # Connect signals: when thread starts, call run_scan with UI parameters
        self.thread.started.connect(lambda: self.worker.run_scan(target, int(self.start_port.text()), int(self.end_port.text())))
        
        # Connect worker signals to update the UI (logs, progress bar, status text)
        self.worker.log_signal.connect(self.output_area.append)
        self.worker.progress_signal.connect(self.progress_bar.setValue)
        self.worker.current_port_signal.connect(lambda p: self.status_monitor.setText(f"Scanning Port: {p}..."))
        self.worker.finished_signal.connect(self.on_scan_finished)
        
        self.thread.start()

    def analyze_results(self, ports):
        """Performs a basic security assessment based on found open ports."""
        self.output_area.append("\n" + "="*40)
        self.output_area.append("🛡️ SECURITY AUDIT REPORT")
        self.output_area.append("="*40)

        # Define 'risk weights' for specific ports (3 = high risk, 1 = low risk)
        risk_points = {
            21: 3, 22: 1, 23: 3, 25: 2, 53: 2, 80: 2,
            443: 1, 445: 3, 3306: 3, 3389: 3, 8080: 2
        }

        # Known banners/signatures associated with vulnerabilities
        risky_versions = {
            "OpenSSH_7.2": "⚠️ Outdated SSH version detected.",
            "vsftpd 2.3.4": "⚠️ Known vulnerable FTP version.",
            "Microsoft-HTTPAPI": "⚠️ Possible Windows HTTP vulnerability."
        }

        total_score = 100
        risk_sum = 0

        for port in ports:
            # Get specific advice for this port or use a default message
            suggestion = SUGGESTIONS.get(port, "Custom Service: Verify intent. Close if not needed.")
            risk_sum += risk_points.get(port, 2) # Default to risk 2 if not in list
            
            # Check if the service banner contains a risky version signature
            banner = getattr(self.worker, 'last_banner', None)
            risk_tag = ""
            if banner:
                for sig, msg in risky_versions.items():
                    if sig in banner:
                        risk_tag = f" {msg}"
                        break
            self.output_area.append(f"• Port {port}: {suggestion}{risk_tag}")

        # Calculate a percentage-based security score
        max_possible_risk = max(len(ports) * 3, 1)
        security_score = max(0, total_score - int((risk_sum / max_possible_risk) * 100))

        # Output the final security verdict
        self.output_area.append("\n" + "-"*40)
        self.output_area.append(f"💡 Target Security Score: {security_score}%")
        
        if security_score > 70:
            self.output_area.append("✅ Target is relatively safe.")
        elif security_score > 40:
            self.output_area.append("⚠️ Moderate risk detected.")
        else:
            self.output_area.append("❌ High risk detected!")
        self.output_area.append("="*40 + "\n")

    def stop_scanning(self):
        """Safely stops the worker and shuts down the background thread."""
        if self.worker:
            self.worker.stop()
        if self.thread:
            self.thread.quit()
            self.thread.wait()
        
        # Reset UI button to 'Start' mode with a green color
        self.scan_btn.setText("START SCAN")
        self.scan_btn.setStyleSheet("background-color: #238636;")
        self.progress_bar.setValue(0)

    def on_scan_finished(self, found_ports):
        """Callback triggered when the scanning worker finishes its task."""
        self.status_monitor.setText("Scan Complete.")
        self.stop_scanning()
        
        if found_ports:
            # Store results and trigger the security analysis
            self.worker.found_ports = found_ports
            self.analyze_results(found_ports)
        else:
            self.output_area.append("[*] No open ports found.")

    def save_log(self):
        """Exports the scan results to either an HTML report or a plain text file."""
        # Ensure there is data to save
        ports = getattr(self.worker, 'found_ports', [])
        if not ports:
            self.output_area.append("[!] No scan data available to save.")
            return

        # Open a file dialog to choose save location and format
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "scan_report.html",
            "HTML Files (*.html);;Text Files (*.txt)"
        )

        if not path:
            return

        # Handle different file extensions
        if path.endswith(".html"):
            self.save_html_report(ports, path)
        else:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.output_area.toPlainText())
            self.output_area.append(f"[*] Report saved to {path}")

    # Define a method to generate and save an HTML-based security report
def save_html_report(self, ports, filename="scan_report.html"):
    # Capture the current date and time for the report header
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Map specific port numbers to risk weights (1 = Low, 2 = Medium, 3 = High)
    risk_points = {
        21: 3, 22: 1, 23: 3, 25: 2, 53: 2, 80: 2,
        443: 1, 445: 3, 3306: 3, 3389: 3, 8080: 2
    }

    # Dictionary containing specific service version strings that indicate vulnerabilities
    risky_versions = {
        "OpenSSH_7.2": "⚠️ Outdated SSH version detected.",
        "vsftpd 2.3.4": "⚠️ Known vulnerable FTP version.",
        "Microsoft-HTTPAPI": "⚠️ Possible Windows HTTP vulnerability."
    }

    # Calculate the total risk value of the discovered open ports
    # Defaults to a risk of 2 if the port is not in the risk_points map
    risk_sum = sum(risk_points.get(p, 2) for p in ports)
    
    # Calculate the maximum possible risk to normalize the score
    max_possible_risk = max(len(ports) * 3, 1)
    
    # Convert the risk total into a percentage-based security score (100 is best)
    security_score = max(0, 100 - int((risk_sum / max_possible_risk) * 100))

    # Construct the HTML structure, including CSS for dark-mode styling and risk coloring
    html = f"""
    <html>
    <head>
        <title>Security Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #0d1117; color: #d1d5da; }}
            h1 {{ color: #238636; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #30363d; padding: 8px; text-align: left; }}
            th {{ background-color: #161b22; }}
            tr:nth-child(even) {{ background-color: #0d1117; }}
            .risk-low {{ color: #2ea043; font-weight: bold; }}
            .risk-medium {{ color: #d29922; font-weight: bold; }}
            .risk-high {{ color: #da3633; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>🛡️ Security Scan Report</h1>
        <p><strong>Target:</strong> {self.target_input.text()}</p>
        <p><strong>Scan Time:</strong> {now}</p>
        <p><strong>Security Score:</strong> {security_score}%</p>
        <table>
            <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Banner</th>
                <th>Risk</th>
            </tr>
    """

    # Iterate through found ports to build individual table rows
    for port in ports:
        # Get service name from global SUGGESTIONS or default to 'Custom Service'
        suggestion = SUGGESTIONS.get(port, "Custom Service")
        # Retrieve the service banner captured during the scan
        banner = getattr(self.worker, 'last_banner', 'N/A')
        
        # Determine CSS class based on risk points
        risk_class = "risk-medium"
        if risk_points.get(port, 2) == 3:
            risk_class = "risk-high"
        elif risk_points.get(port, 2) == 1:
            risk_class = "risk-low"

        # Check the banner string against known risky version signatures
        risk_tag = ""
        if banner:
            for sig, msg in risky_versions.items():
                if sig in banner:
                    risk_tag = msg
                    break

        # Append the formatted row for this specific port to the HTML string
        html += f"""
            <tr>
                <td>{port}</td>
                <td>{suggestion}</td>
                <td>{banner}</td>
                <td class="{risk_class}">{risk_tag or risk_class.replace('risk-', '').capitalize()}</td>
            </tr>
        """

    # Close the HTML tags
    html += """
        </table>
    </body>
    </html>
    """

    # Write the completed HTML string to a file using UTF-8 encoding
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    # Import the webbrowser module and open the report file in the system default browser
    import webbrowser
    webbrowser.open(filename)

# Application entry point: setup and run the GUI
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CyberToolGUI()
    window.show()
    sys.exit(app.exec())