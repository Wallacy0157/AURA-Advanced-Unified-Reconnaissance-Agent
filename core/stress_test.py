import socket
import threading
import time
import json
import csv
import ssl
import os
from datetime import datetime

class StressTestExecutor:
    def __init__(self, target, port, rps_limit=10, duration=60, gradual=False):
        self.target = target
        self.port = port
        self.rps_limit = rps_limit
        self.duration = duration
        self.gradual = gradual
        self.is_running = False
        self.results = []

        # Única fonte de dados para a UI
        self.stats = {
            "success": 0, 
            "timeout_drop": 0, 
            "reset_reject": 0,
            "errors": 0, 
            "total_sent": 0, 
            "avg_latency": 0.0
        }

    import ssl

    def _probe(self):
        start_time = time.time()
        timestamp = datetime.now().isoformat()
        status = "unknown"
        latency = 0

        try:
            self.stats["total_sent"] += 1

            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(3.0)

            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # ambiente controlado

            tls_sock = context.wrap_socket(
                raw_sock,
                server_hostname=self.target
            )

            conn_start = time.time()
            tls_sock.connect((self.target, self.port))
            latency = (time.time() - conn_start) * 1000

            tls_sock.sendall(
                b"GET / HTTP/1.1\r\n"
                b"Host: aura.test\r\n"
                b"Connection: close\r\n\r\n"
            )

            status = "SUCCESS"
            self.stats["success"] += 1

            tls_sock.close()

        except ssl.SSLError:
            status = "TLS_ERROR"
            self.stats["errors"] += 1

        except socket.timeout:
            status = "DROP (Timeout)"
            self.stats["timeout_drop"] += 1

        except ConnectionResetError:
            status = "REJECT (RST)"
            self.stats["reset_reject"] += 1

        except Exception:
            status = "ERROR"
            self.stats["errors"] += 1

        if status == "SUCCESS":
            old_avg = self.stats["avg_latency"]
            self.stats["avg_latency"] = (
                (old_avg + latency) / 2 if old_avg > 0 else latency
            )

        self.results.append({
            "timestamp": timestamp,
            "port": self.port,
            "status": status,
            "latency_ms": round(latency, 2)
        })


    def run(self):
        self.is_running = True
        start_test = time.time()
        current_rps = 1.0 if self.gradual else float(self.rps_limit)

        while self.is_running and (time.time() - start_test) < self.duration:
            cycle_start = time.time()
            
            for _ in range(int(current_rps)):
                if not self.is_running: break
                threading.Thread(target=self._probe, daemon=True).start()
            
            if self.gradual and current_rps < self.rps_limit:
                current_rps *= 1.1

            sleep_time = 1.0 - (time.time() - cycle_start)
            if sleep_time > 0:
                time.sleep(sleep_time)

        self.is_running = False
        self.export_evidence()

    def export_evidence(self):
        if not os.path.exists("logs"): os.makedirs("logs")
        filename = f"logs/stress_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        with open(f"{filename}.json", "w") as f:
            json.dump({"summary": self.stats, "data": self.results}, f, indent=4)
            
        if self.results:
            keys = self.results[0].keys()
            with open(f"{filename}.csv", "w", newline='') as f:
                dict_writer = csv.DictWriter(f, fieldnames=keys)
                dict_writer.writeheader()
                dict_writer.writerows(self.results)
