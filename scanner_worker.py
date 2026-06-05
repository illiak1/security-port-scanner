import socket 
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed 
from datetime import datetime 
from PyQt6.QtCore import QObject, pyqtSignal 
import ssl

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

class ScannerWorker(QObject):
    log_signal = pyqtSignal(str)          
    progress_signal = pyqtSignal(int)     
    current_port_signal = pyqtSignal(int) 
    finished_signal = pyqtSignal(dict)    

    def __init__(self):
        super().__init__()
        self._is_running = True  
        self.timeout = 0.8       
        self._executor = None 
        self.scan_results = {}  # Fixed: Keep track of results natively

    def ping_host(self, target_ip):
        """Performs an ICMP ping check to see if the host is up before scanning."""
        # Determine current operating system flag for ping count
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', target_ip]
        
        try:
            # Run background ping without spawning a black CMD window
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2.0)
            return result.returncode == 0
        except Exception:
            return False

    def grab_banner(self, s):
        """Attempts to retrieve the service identification string."""
        try:
            s.settimeout(1.0)
            try:
                s.sendall(b"\r\n")
                s.settimeout(0.3)
            except OSError:
                pass

            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else None
        except (socket.timeout, OSError):
            return None    

    def _probe_http(self, sock, hostname):
        """Helper to send a lightweight HEAD request."""
        try:
            request = f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\nUser-Agent: SecurityScanner/1.0\r\n\r\n".encode()
            sock.sendall(request)
            return sock.recv(1024).decode("utf-8", errors="ignore").strip()
        except (socket.timeout, OSError):
            return None

    def check_port(self, target_ip, target_hostname, port):
        """Attempts to identify the service and retrieve its banner/headers."""
        if not self._is_running:
            return None

        try:
            with socket.create_connection((target_ip, port), timeout=self.timeout) as s:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"

                banner = None

                if port in (80, 8080):
                    banner = self._probe_http(s, target_hostname)
                    if not banner:  
                        banner = self.grab_banner(s)
                elif port == 443:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE

                        with context.wrap_socket(s, server_hostname=target_hostname) as tls_sock:
                            tls_sock.settimeout(self.timeout)
                            banner = self._probe_http(tls_sock, target_hostname)
                    except (ssl.SSLError, socket.timeout, OSError):
                        pass
                else:
                    banner = self.grab_banner(s)

                return port, service, banner
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

    def run_scan(self, target, start_port, end_port):
        """Orchestrates the multi-threaded scanning process."""
        self._is_running = True
        self.scan_results = {} 
        self.log_signal.emit(f"[*] Initializing deep scan on {target}...")

        try:
            addr_info = socket.getaddrinfo(target, None)[0]
            target_ip = addr_info[4][0]
        except socket.gaierror:
            self.log_signal.emit("[!] Error: Resolution failed.")
            self.finished_signal.emit({})
            return

        # --- Extra Pre-Check: Ping Host ---
        self.log_signal.emit("[*] Checking if host is online (Ping)...")
        if not self.ping_host(target_ip):
            self.log_signal.emit("[⚠️] Warning: Host did not respond to ICMP ping. Proceeding with port scan anyway...")
        else:
            self.log_signal.emit("[+] Host is online and responding.")

        ports = range(start_port, end_port + 1)
        total = len(ports)

        if total == 0:
            self.finished_signal.emit({})
            return

        with ThreadPoolExecutor(max_workers=100) as executor:
            self._executor = executor
            future_to_port = {
                executor.submit(self.check_port, target_ip, target, p): p for p in ports
            }
            
            for i, future in enumerate(as_completed(future_to_port)):
                current_p = future_to_port[future]
                
                if not self._is_running:
                    break
                
                try:
                    res = future.result()
                except Exception as e:
                    self.log_signal.emit(f"[!] Worker error on port {current_p}: {e}")
                    continue    
                
                if res:
                    port, service, banner = res
                    self.scan_results[port] = {"service": service, "banner": banner}
                    output = f"[+] [OPEN] Port {port:<5} | Service: {service}"
                    
                    if banner and banner.strip():
                        clean_banner = banner.splitlines()[0][:100].strip()
                        output += f"\n    ┗━ [BANNER]: {clean_banner}"
                    
                    if port in SUGGESTIONS:
                        output += f"\n    ┗━ [NOTE]: {SUGGESTIONS[port]}"
                        
                    self.log_signal.emit(output)

                self.current_port_signal.emit(current_p)
                if i % 10 == 0 or i == total - 1:
                    self.progress_signal.emit(int(((i + 1) / total) * 100))

        self.log_signal.emit(f"\n--- Scan Finished: {datetime.now().strftime('%H:%M:%S')} ---")
        self.finished_signal.emit(self.scan_results)

    def stop(self):
        self._is_running = False
        if self._executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
