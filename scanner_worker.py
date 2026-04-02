import socket  # Provides access to the BSD socket interface for network connections
from concurrent.futures import ThreadPoolExecutor, as_completed  # Enables multi-threading for faster scanning
from datetime import datetime  # Used to timestamp the end of the scan
from PyQt6.QtCore import QObject, pyqtSignal  # Integration with Qt framework for GUI

# A mapping of common ports to security advice and descriptions
SUGGESTIONS = {
    21: "FTP: Insecure. Suggest switching to SFTP (Port 22) or FTPS.",
    22: "SSH: Secure, but Ensure key-based auth is used and root login is disabled.",
    23: "Telnet: Highly Insecure. Disable immediately and use SSH.",
    25: "SMTP: Check for open relays to prevent mail spoofing.",
    53: "DNS: Ensure it is not vulnerable to DDoS amplification attacks.",
    80: "HTTP: Unencrypted. Consider redirecting to HTTPS (Port 443).",
    110: "POP3: Cleartext passwords. Use POP3S (995) instead.",
    139: "NetBIOS: Risk of information disclosure. Block at firewall if not local.",
    443: "HTTPS: Secure. Keep SSL/TLS certificates up to date.",
    445: "SMB: High risk (WannaCry/EternalBlue). Ensure latest patches or disable if not needed.",
    3306: "MySQL: Risk of brute force. Do not expose to the public internet.",
    3389: "RDP: High risk for ransomware. Use a VPN or MFA instead of public exposure.",
    8080: "HTTP Proxy/Alt: Often used for dev. Ensure it's not exposing sensitive debug info."
}

# Worker class that handles the scanning logic in a separate thread to keep the GUI responsive
class ScannerWorker(QObject):
    # Signals to communicate back to the main UI thread
    log_signal = pyqtSignal(str)          # Sends text logs to the UI
    progress_signal = pyqtSignal(int)     # Sends percentage completion (0-100)
    current_port_signal = pyqtSignal(int) # Sends the port currently being scanned
    finished_signal = pyqtSignal(list)    # Sends the final list of open ports when done

    def __init__(self):
        super().__init__()
        self._is_running = True  # Flag to allow stopping the scan prematurely
        self.timeout = 0.8       # Seconds to wait for a response from a port

    def grab_banner(self, s):
        """Attempts to retrieve the service identification string (banner) from an open socket."""
        try:
            s.send(b'Hello\r\n')  # Send a generic probe to trigger a response
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else None
        except:
            return None

    def check_port(self, target, port):
        """Attempts to connect to a specific port on the target IP."""
        if not self._is_running:
            return None
        try:
            # Create a TCP socket using AF_INET (IPv4) and SOCK_STREAM (TCP)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                # connect_ex returns 0 if the connection is successful (port is open)
                result = s.connect_ex((target, port))
                
                if result == 0:
                    try:
                        # Attempt to resolve the common service name for this port
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    # Try to get more info via banner grabbing
                    banner = self.grab_banner(s)
                    return port, service, banner
        except:
            return None
        return None

    def run_scan(self, target, start_port, end_port):
        """The main loop that orchestrates the multi-threaded scanning process."""
        found_ports = []
        self.log_signal.emit(f"[*] Initializing deep scan on {target}...")

        try:
            # Convert hostname (e.g., 'google.com') to an IP address
            target_ip = socket.gethostbyname(target)
        except socket.gaierror:
            self.log_signal.emit("[!] Error: Resolution failed.")
            self.finished_signal.emit([])
            return

        ports = range(start_port, end_port + 1)
        total = len(ports)

        # ThreadPoolExecutor manages a pool of threads to scan multiple ports simultaneously
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Map each port check to a future object
            future_to_port = {executor.submit(self.check_port, target_ip, p): p for p in ports}
            
            # As each thread completes, process the result
            for i, future in enumerate(as_completed(future_to_port)):
                if not self._is_running:
                    break
                
                res = future.result()
                if res:
                    port, service, banner = res
                    found_ports.append(port)
                    output = f"[+] [OPEN] Port {port:<5} | Service: {service}"
                    if banner:
                        output += f"\n    ┗━ [BANNER]: {banner[:100]}"
                    self.log_signal.emit(output)

                # Update the UI on progress
                self.current_port_signal.emit(future_to_port[future])
                if i % 10 == 0 or i == total - 1:
                    self.progress_signal.emit(int(((i + 1) / total) * 100))

        # Finalize and notify the UI
        self.log_signal.emit(f"\n--- Scan Finished: {datetime.now().strftime('%H:%M:%S')} ---")
        self.finished_signal.emit(found_ports)

    def stop(self):
        """Sets the running flag to False to halt the scan."""
        self._is_running = False