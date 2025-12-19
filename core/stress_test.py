import socket
import threading
import time
import json
import csv
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

    def _probe(self):
        """Envia a sonda e atualiza a 'gaveta' stats que a UI lê."""
        start_time = time.time()
        timestamp = datetime.now().isoformat()
        status = "unknown"
        latency = 0
        
        try:
            # Incrementa tentativa antes de enviar
            self.stats["total_sent"] += 1
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3.0) 
            
            conn_result = s.connect_ex((self.target, self.port))
            latency = (time.time() - start_time) * 1000 
            
            if conn_result == 0:
                status = "SUCCESS"
                self.stats["success"] += 1
                s.send(b"GET / HTTP/1.1\r\nHost: aura.test\r\n\r\n")
            elif conn_result in [111, 10061]: # Connection Refused
                status = "REJECT (RST)"
                self.stats["reset_reject"] += 1
            elif conn_result in [110, 10060]: # Timeout
                status = "DROP (Timeout)"
                self.stats["timeout_drop"] += 1
            else:
                status = f"ERROR_{conn_result}"
                self.stats["errors"] += 1
                
            s.close()
        except Exception:
            status = "DROP (Timeout)"
            self.stats["timeout_drop"] += 1
            
        # Atualiza latência média
        if status == "SUCCESS":
            old_avg = self.stats["avg_latency"]
            self.stats["avg_latency"] = (old_avg + latency) / 2 if old_avg > 0 else latency
        
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
