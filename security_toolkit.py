# AURA/security_toolkit.py

import os
import sys
import json
import re 
from datetime import datetime

# Importações PyQt6
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
    QMessageBox
)
from random import randint 

# Importações de módulos internos 
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
# (Código mantido)
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
# (Código mantido)
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
        # (Código mantido)
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
        # (Código mantido)
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
        # (Código mantido)
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
        # (Código mantido)
        self.start_button.setEnabled(True)
        self.parent_window.status_label.setText("ERRO durante varredura!")
        self.results_text.setText(f"Um erro inesperado ocorreu: {message}. Verifique se o Nmap está instalado e se você tem permissões de sudo.")
        self.last_results = None

    def save_results(self):
        # (Código mantido)
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


# --- CLASSE PRINCIPAL (MainWindow) ---

class MainWindow(QMainWindow):
    def __init__(self, base_dir):
        super().__init__()
        self.base_dir = base_dir
        
        self.user_settings = load_user_settings(self.base_dir)
        
        self.theme_manager = ThemeManager(self.user_settings)
        
        self.current_lang_code = self.user_settings.get('language', 'pt') 
        self.L = load_language_json(self.current_lang_code, self.base_dir) # ⚠️ Passa base_dir
        
        self.setWindowTitle("AURA Security Toolkit")
        self.setGeometry(100, 100, 1200, 800)
        
        self._build_ui()
        
        self._apply_theme(self.theme_manager.current_theme) 
        self.update_ui_language(self.current_lang_code)

    def _build_ui(self):
        # (Código mantido, apenas a parte que cria o layout principal)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # --- Sidebar ---
        self.sidebar = QFrame()
        self.sidebar.setFixedWidth(200)
        self.sidebar.setObjectName("Sidebar")
        
        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(10, 20, 10, 10)
        sidebar_layout.setSpacing(10)
        
        self.title_label = QLabel("AURA")
        self.title_label.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setContentsMargins(0, 0, 0, 20)
        self.title_label.setObjectName("AuraTitle")
        sidebar_layout.addWidget(self.title_label)
        
        # ... (Criação dos botões da sidebar) ...
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
        self.status_label.setFont(QFont("Arial", 10))
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sidebar_layout.addWidget(self.status_label)
        
        main_layout.addWidget(self.sidebar)

        # --- Área de Conteúdo Principal ---
        # ⚠️ Novo: Centraliza o widget principal que contém as páginas
        self.content_frame = QFrame() 
        self.content_frame.setObjectName("ContentFrame") # ID para estilizar o fundo
        content_v_layout = QVBoxLayout(self.content_frame)
        content_v_layout.setContentsMargins(0, 0, 0, 0)
        content_v_layout.setSpacing(0)
        
        self.pages = QStackedWidget()
        
        # ... (Criação das páginas - Home, Tools, Scanner, Scripts, Logs, Config) ...
        
        # Index 0: Home
        home = QWidget()
        home.setObjectName("PageWidget") # ID para estilizar o fundo das páginas
        home_layout = QVBoxLayout(home)
        
        self.welcome_label = QLabel("Bem-vindo ao AURA Security Toolkit!")
        self.welcome_label.setFont(QFont("Arial", 16, QFont.Weight.Bold))
        self.welcome_label.setContentsMargins(0, 0, 0, 10)
        home_layout.addWidget(self.welcome_label)
        
        # Cards (mantidos)
        card_layout = QHBoxLayout()
        self.card_scanner = NeonCard(
            icon="🛰️", title="Varredura de Rede", 
            subtitle="Identifica hosts, portas abertas e vulnerabilidades.", 
            neon_color=self.theme_manager.neon_color, 
            theme_manager=self.theme_manager
        )
        self.card_scanner.on_card_activated = lambda: self.pages.setCurrentIndex(2) 
        
        self.card_bruteforce = NeonCard(
            icon="🔒", title="Brute Force", 
            subtitle="Ferramenta para testar a força de credenciais.", 
            neon_color=self.theme_manager.neon_color, 
            theme_manager=self.theme_manager
        )
        self.card_bruteforce.on_card_activated = lambda: self.status_label.setText("Funcionalidade Brute Force em desenvolvimento...")
        
        self.card_firewall = NeonCard(
            icon="🚧", title="Teste de Firewall", 
            subtitle="Verifica regras e filtros de segurança de rede.", 
            neon_color=self.theme_manager.neon_color, 
            theme_manager=self.theme_manager
        )
        self.card_firewall.on_card_activated = lambda: self.status_label.setText("Funcionalidade Teste de Firewall em desenvolvimento...")
        
        card_layout.addWidget(self.card_scanner)
        card_layout.addWidget(self.card_bruteforce)
        card_layout.addWidget(self.card_firewall)
        
        home_layout.addLayout(card_layout)
        home_layout.addStretch()

        self.pages.addWidget(home) # Index 0 
        
        tools_page = QWidget()
        tools_page.setObjectName("PageWidget")
        tools_layout = QVBoxLayout(tools_page)
        tools_layout.addWidget(QLabel("Página Ferramentas - em desenvolvimento"))
        self.pages.addWidget(tools_page) # Index 1
        
        self.scanner_page = ScannerPage(self)
        self.scanner_page.setObjectName("PageWidget")
        self.pages.addWidget(self.scanner_page) # Index 2
        
        scripts_page = QWidget()
        scripts_page.setObjectName("PageWidget")
        scripts_layout = QVBoxLayout(scripts_page)
        scripts_layout.addWidget(QLabel("Página Scripts - em desenvolvimento"))
        self.pages.addWidget(scripts_page) # Index 3
        
        logs_page = QWidget()
        logs_page.setObjectName("PageWidget")
        logs_layout = QVBoxLayout(logs_page)
        logs_layout.addWidget(QLabel("Página Logs - em desenvolvimento"))
        self.pages.addWidget(logs_page)      # Index 4
        
        self.config_page = ConfigPage(self)
        self.config_page.setObjectName("PageWidget")
        self.pages.addWidget(self.config_page) # Index 5

        content_v_layout.addWidget(self.pages)
        main_layout.addWidget(self.content_frame) # Adiciona ContentFrame

        # ... (Conexões dos botões mantidas) ...
        self.btn_home.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        self.btn_tools.clicked.connect(lambda: self.pages.setCurrentIndex(1))
        self.btn_scanner.clicked.connect(lambda: self.pages.setCurrentIndex(2))
        self.btn_scripts.clicked.connect(lambda: self.pages.setCurrentIndex(3))
        self.btn_logs.clicked.connect(lambda: self.pages.setCurrentIndex(4))
        self.btn_config.clicked.connect(lambda: self.pages.setCurrentIndex(5))

    def _make_sidebar_button(self, text, icon):
        # (Código mantido)
        btn = QPushButton(f"  {icon} {text}")
        btn.setObjectName("SidebarButton")
        btn.setFixedHeight(40)
        btn.setFont(QFont("Arial", 12))
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet("""
            QPushButton#SidebarButton { 
                text-align: left; 
                padding-left: 15px; 
            }
        """)
        return btn

    # ----------------- Gerenciamento de Tema -----------------

    def get_theme_colors(self, theme_key=None):
        # (Código mantido)
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
        
        # Atualiza a cor neon em todos os NeonCards
        for card in self.findChildren(NeonCard):
            card.set_neon_color(neon_color, self.theme_manager.current_theme)


    # ----------------- Métodos de Configuração (Chamados pela ConfigPage) -----------------

    def apply_base_theme(self, theme_name):
        # (Código mantido)
        self.theme_manager.set_base_theme(theme_name)
        self._apply_theme(theme_name)
        
    def set_global_neon_color(self, color):
        # (Código mantido)
        self.theme_manager.set_neon_color(color)
        self._apply_theme(self.theme_manager.current_theme) 

    def apply_language(self, lang_name):
        """Chamado pela ConfigPage para mudar o idioma."""
        
        lang_map = {
            "Português": "pt", "Inglês": "en", "Espanhol": "es", 
            "Francês": "fr", "Alemão": "de", "Italiano": "it",
            "Russo": "ru", "Chinês": "zh", "Coreano": "ko", 
            "Japonês": "ja", "Árabe": "ar"
        }
        
        lang_code = lang_map.get(lang_name, "pt")
        
        # ⚠️ CORREÇÃO: Carrega o novo dicionário L antes de atualizar a UI
        new_L = load_language_json(lang_code, self.base_dir) 
        self.L = new_L
        self.current_lang_code = lang_code
        
        self.update_ui_language(lang_code)
        
    # ----------------- Atualização de Idioma -----------------

    def update_ui_language(self, lang_code):
        """Atualiza todos os textos da UI com base no dicionário de idioma carregado (self.L)."""
        L = self.L 
        
        # Sidebar
        self.btn_home.setText("  " + lang_get(L, "sidebar.home", "🏠 Home"))
        self.btn_tools.setText("  " + lang_get(L, "sidebar.tools", "🛠️ Ferramentas"))
        self.btn_scanner.setText("  " + lang_get(L, "sidebar.scanner", "🛰️ Scanner")) 
        self.btn_scripts.setText("  " + lang_get(L, "sidebar.scripts", "📜 Scripts"))
        self.btn_logs.setText("  " + lang_get(L, "sidebar.logs", "📁 Logs"))
        self.btn_config.setText("  " + lang_get(L, "sidebar.settings", "⚙️ Configurações"))
        self.status_label.setText(lang_get(L, "header.status_ready", "Status: Pronto"))

        self.config_page.update_ui_language(L) 
        self.scanner_page.update_ui_language(L)
        
        # Atualização da Página Home
        self.welcome_label.setText(lang_get(L, "home_page.welcome", "Bem-vindo ao AURA Security Toolkit!")) 
        
        # Cards na Home (Ajustei as chaves para corresponder ao seu en.json/pt.json completo)
        self.card_scanner.set_texts(
            lang_get(L, "cards.scanner.title", "Varredura de Rede"),
            lang_get(L, "cards.scanner.subtitle", "Varre e detecta hosts")
        )
        self.card_bruteforce.set_texts(
            lang_get(L, "cards.advanced.title", "Modo Avançado (Ex. Brute Force)"), # Usando uma chave temporária
            lang_get(L, "cards.advanced.subtitle", "Funções extras / DevTools")
        )
        self.card_firewall.set_texts(
            lang_get(L, "cards.ports.title", "Analisador de Portas (Ex. Firewall)"), # Usando uma chave temporária
            lang_get(L, "cards.ports.subtitle", "Testa portas específicas")
        )
        
        self.current_lang_code = lang_code 


    # ----------------- closeEvent (Persistência) -----------------
    
    def closeEvent(self, event):
        # (Código mantido)
        self.user_settings['language'] = self.current_lang_code
        self.user_settings['theme'] = self.theme_manager.current_theme
        self.user_settings['neon_color'] = self.theme_manager.neon_color
        
        save_user_settings(self.base_dir, self.user_settings)
        
        super().closeEvent(event)

# --- EXECUÇÃO PRINCIPAL ---
#test

if __name__ == "__main__":
    
    if getattr(sys, 'frozen', False):
        base_dir = os.path.dirname(sys.executable)
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))

    app = QApplication(sys.argv)
    
    # ⚠️ CORREÇÃO: Aplica a paleta inicial corretamente (opcional, mas bom)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(THEMES['dark']['bg_main']))
    app.setPalette(palette)
    
    window = MainWindow(base_dir)
    window.show()
    sys.exit(app.exec())
