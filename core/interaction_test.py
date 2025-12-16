# AURA/core/interaction_test.py

import os
import subprocess
import webbrowser
import time
from datetime import datetime
from PyQt6.QtWidgets import QMessageBox, QApplication

def run_interaction_test(parent_window):
    base_dir = parent_window.base_dir
    log_path = os.path.join(base_dir, "logs", "teste_seguranca.log")
    results = []

    # Pergunta inicial: "Deseja iniciar o teste de stress?"
    confirm = QMessageBox.question(
        parent_window, "AURA Security",
        "Este teste executará ações sensíveis (abrir abas, tentar acesso a pastas).\nDeseja continuar?",
        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
    )

    if confirm == QMessageBox.StandardButton.No:
        return

    parent_window.status_label.setText("Executando teste de stress...")

    with open(log_path, "a", encoding="utf-8") as log:
        log.write(f"\n--- RELATÓRIO DE SEGURANÇA: {datetime.now()} ---\n")

        # --- TESTE 1: Acesso a Pastas Protegidas ---
        parent_window.status_label.setText("Testando acesso a pastas...")
        pasta_alvo = "/root" if os.name != 'nt' else "C:\\Windows\\System32\\config"
        try:
            os.listdir(pasta_alvo)
            res = "SUCESSO (Vulnerável: Acesso permitido a pasta sensível)"
        except PermissionError:
            res = "BLOQUEADO (Seguro: Acesso negado pelo sistema)"
        results.append(f"Acesso a {pasta_alvo}: {res}")

        # --- TESTE 2: Execução de Processos (Simulação) ---
        parent_window.status_label.setText("Testando execução de subprocesso...")
        try:
            # Tenta rodar um comando simples de sistema
            subprocess.run(["whoami"], check=True, capture_output=True)
            res = "SUCESSO (Execução de scripts permitida)"
        except Exception as e:
            res = f"FALHA (Bloqueado: {e})"
        results.append(f"Execução de subprocessos: {res}")

        # --- TESTE 3: Loop de Navegador (Evasão/Spam) ---
        parent_window.status_label.setText("Abrindo abas no navegador...")
        for i in range(5):
            try:
                webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ") # Rickroll de teste
                log.write(f"Aba {i+1} aberta.\n")
                time.sleep(0.5) # Para não travar o PC do usuário
            except:
                pass
        results.append("Abertura de abas: Concluído (Verifique se as 5 abriram)")

        # --- GRAVANDO RESULTADOS NO LOG ---
        for r in results:
            log.write(r + "\n")
        log.write("-" * 40 + "\n")

    # --- RELATÓRIO FINAL NA TELA ---
    resultado_final = "\n".join(results)
    QMessageBox.information(
        parent_window, 
        "Resultado do Teste", 
        f"O teste terminou! Veja o que aconteceu:\n\n{resultado_final}\n\nLog: {log_path}"
    )
    parent_window.status_label.setText("Status: Pronto")
