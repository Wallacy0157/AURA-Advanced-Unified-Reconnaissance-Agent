#!/usr/bin/env python3
"""
Security Toolkit - PyQt6 Dark Neon Dashboard com Configurações

Versão final:
- Suporte a idiomas via JSON (carrega de ./languages/*.json)
- ConfigPage com opções de tema, cor neon, temas especiais e idioma
- Atualização dinâmica de texto da interface
- Mantém visual neon e comportamento do painel
"""

import sys
import json
import os
from PyQt6.QtCore import Qt, QTimer, QTime, QSize, QPropertyAnimation
from PyQt6.QtGui import QIcon, QFont, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QHBoxLayout, QVBoxLayout,
    QGridLayout, QToolButton, QPushButton, QStackedWidget, QFrame,
    QSizePolicy, QLineEdit, QGraphicsDropShadowEffect, QGroupBox, QRadioButton,
    QComboBox, QSpacerItem
)

# ---------------- Config (cores, paths) ----------------
NEON_DEFAULT = "#7b4dff"
BACKGROUND_DARK = "#0d0d0d"
BACKGROUND_LIGHT = "#f5f5f5"
CARD_BG = "#131313"
CARD_BORDER = "#2a2a2a"
CARD_BORDER_LIGHT = "#d3d3d3"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LANG_DIR = os.path.join(BASE_DIR, "languages")

# ---------------- Helper: leitura de JSON de idioma ----------------
def load_language_json(lang_code):
    """
    Tenta carregar LANG_DIR/{lang_code}.json. Retorna dict (pode ser vazio).
    """
    if not os.path.isdir(LANG_DIR):
        print("Aviso: pasta de idiomas não existe:", LANG_DIR)
        return {}

    path = os.path.join(LANG_DIR, f"{lang_code}.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        print(f"Idioma não encontrado: {path}")
    except Exception as e:
        print("Erro ao carregar idioma:", e)
    return {}

# ---------------- Utility: leitura flexível de strings do JSON ----------------
def lang_get(lang_dict, key, fallback=None):
    """
    Busca a chave de forma flexível no dicionário de idioma.
    key pode ser 'home' ou 'dashboard' ou 'cards.scanner.title' (suporte simples com ponto).
    """
    if not lang_dict:
        return fallback
    
    # chave com caminho 'cards.scanner.title' ou 'settings_page.themes'
    if "." in key:
        parts = key.split(".")
        cur = lang_dict
        for p in parts:
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return fallback
        return cur if isinstance(cur, (str, int)) else fallback

    # Procurar em blocos comuns (apenas por compatibilidade se a chave for solta)
    search_paths = ["sidebar", "header", "settings_page", "settings", "cards"]
    if key in lang_dict:
        return lang_dict[key]
    
    for path in search_paths:
        if path in lang_dict and isinstance(lang_dict[path], dict) and key in lang_dict[path]:
            return lang_dict[path][key]
            
    return fallback

# ---------------- NeonCard ----------------
class NeonCard(QFrame):
    def __init__(self, icon_text: str, title: str, subtitle: str = "", neon_color=NEON_DEFAULT, parent=None):
        super().__init__(parent)
        self.icon_text = icon_text
        self.title = title
        self.subtitle = subtitle
        self.neon_color = neon_color
        self._setup_ui()
        self.setObjectName("neonCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._setup_glow()

    def _setup_ui(self):
        self.setMinimumSize(220, 120)
        self.setMaximumHeight(160)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        layout = QHBoxLayout()
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(12)

        icon = QLabel(self.icon_text)
        icon.setObjectName("cardIcon")
        icon.setFixedSize(56, 56)
        icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_font = QFont()
        icon_font.setPointSize(24)
        icon.setFont(icon_font)

        text_col = QVBoxLayout()
        self.title_label = QLabel(self.title)
        self.title_label.setObjectName("cardTitle")
        self.title_label.setWordWrap(True)
        self.subtitle_label = QLabel(self.subtitle)
        self.subtitle_label.setObjectName("cardSubtitle")

        text_col.addWidget(self.title_label)
        text_col.addWidget(self.subtitle_label)
        text_col.addStretch()

        layout.addWidget(icon)
        layout.addLayout(text_col)
        self.setLayout(layout)
        self.setStyleSheet(self.base_stylesheet())

    def _setup_glow(self):
        self.shadow = QGraphicsDropShadowEffect(self)
        self.shadow.setBlurRadius(10)
        self.shadow.setOffset(0, 0)
        self.shadow.setColor(QColor(self.neon_color))
        self.setGraphicsEffect(self.shadow)

        self.pulse = QPropertyAnimation(self.shadow, b"blurRadius")
        self.pulse.setStartValue(8)
        self.pulse.setEndValue(14)
        self.pulse.setDuration(1000)
        self.pulse.setLoopCount(-1)
        self.pulse.start()

    def base_stylesheet(self):
        return f"""
        QFrame#neonCard {{
            background: {CARD_BG};
            border-radius: 14px;
            border: 2px solid {CARD_BORDER};
        }}
        QLabel#cardIcon {{ color: #ffffff; background: transparent; }}
        QLabel#cardTitle {{ color: #ffffff; font-weight: 700; font-size: 14px; }}
        QLabel#cardSubtitle {{ color: #9aa7b8; font-size: 12px; }}
        """

    def hover_stylesheet(self):
        return f"""
        QFrame#neonCard {{
            background: {CARD_BG};
            border-radius: 14px;
            border: 2px solid {self.neon_color};
        }}
        QLabel#cardIcon {{ color: {self.neon_color}; }}
        QLabel#cardTitle {{ color: #ffffff; font-weight: 800; font-size: 15px; }}
        QLabel#cardSubtitle {{ color: #bfcde6; font-size: 12px; }}
        """

    def enterEvent(self, event):
        self.setStyleSheet(self.hover_stylesheet())
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.setStyleSheet(self.base_stylesheet())
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.on_card_activated()
        super().mousePressEvent(event)

    def on_card_activated(self):
        print(f"Card activated: {self.title}")

    def set_neon_color(self, color):
        # aceita None para remover brilho
        if not color:
            self.neon_color = "#00000000"
        else:
            self.neon_color = color
        try:
            self.shadow.setColor(QColor(self.neon_color))
        except Exception:
            pass
        self.setStyleSheet(self.base_stylesheet())

    def set_texts(self, title, subtitle):
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)

# ---------------- ConfigPage ----------------
class ConfigPage(QWidget):
    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(20)

        # Tema Claro/Escuro
        self.theme_group = QGroupBox("Tema do App")
        theme_layout = QHBoxLayout()
        self.light_theme_btn = QRadioButton("Claro")
        self.dark_theme_btn = QRadioButton("Escuro")
        self.dark_theme_btn.setChecked(True)
        theme_layout.addWidget(self.light_theme_btn)
        theme_layout.addWidget(self.dark_theme_btn)
        self.theme_group.setLayout(theme_layout)
        layout.addWidget(self.theme_group)
        self.light_theme_btn.toggled.connect(lambda: self.change_theme("light"))
        self.dark_theme_btn.toggled.connect(lambda: self.change_theme("dark"))

        # Cor Neon
        self.neon_group = QGroupBox("Cor dos Cards")
        neon_layout = QHBoxLayout()
        self.neon_combo = QComboBox()
        self.neon_combo.setObjectName("NeonColorCombo")
        self.neon_combo.addItems(["Roxo", "Vermelho", "Verde", "Azul", "Rosa", "Amarelo", "Sem luz"]) 
        neon_layout.addWidget(self.neon_combo)
        self.neon_group.setLayout(neon_layout)
        layout.addWidget(self.neon_group)
        self.neon_combo.currentTextChanged.connect(self.change_neon_color)

        # Temas especiais
        self.special_group = QGroupBox("Temas Especiais")
        special_layout = QHBoxLayout()
        self.special_combo = QComboBox()
        self.special_combo.setObjectName("SpecialThemeCombo")
        self.special_combo.addItems(["Nenhum", "Natal", "Halloween", "Páscoa", "Brasil"])
        special_layout.addWidget(self.special_combo)
        self.special_group.setLayout(special_layout)
        layout.addWidget(self.special_group)
        self.special_combo.currentTextChanged.connect(self.change_special_theme)

        # Idioma
        self.lang_group = QGroupBox("Idioma da Interface")
        lang_layout = QHBoxLayout()
        self.lang_combo = QComboBox()
        # FIXO: Lista de idiomas SEMPRE no idioma base (Português),
        # garantindo que o usuário perdido possa achar "Português" ou "Inglês".
        self.lang_combo.addItems([
            "Português", "Inglês", "Espanhol", "Francês", "Italiano",
            "Russo", "Chinês", "Coreano", "Japonês", "Alemão", "Árabe"
        ])
        lang_layout.addWidget(self.lang_combo)
        self.lang_group.setLayout(lang_layout)
        layout.addWidget(self.lang_group)
        self.lang_combo.currentTextChanged.connect(self.change_language)

        layout.addStretch()
        self.setLayout(layout)
        
    def update_ui_language(self, L):
        """Atualiza os textos internos dos widgets de Configuração, exceto a lista de idiomas."""
        
        # Títulos dos GroupBox
        self.theme_group.setTitle(lang_get(L, "settings_page.themes", "Tema do App"))
        self.neon_group.setTitle(lang_get(L, "settings_page.neon_color", "Cor dos Cards"))
        self.special_group.setTitle(lang_get(L, "settings_page.special_themes", "Temas Especiais"))
        self.lang_group.setTitle(lang_get(L, "settings_page.languages", "Idioma da Interface"))
        
        # Radio Buttons
        self.light_theme_btn.setText(lang_get(L, "settings_page.theme_light", "Claro"))
        self.dark_theme_btn.setText(lang_get(L, "settings_page.theme_dark", "Escuro"))

        # QComboBox: Cor Neon
        color_items = [
            lang_get(L, "settings_page.color_purple", "Roxo"),
            lang_get(L, "settings_page.color_red", "Vermelho"),
            lang_get(L, "settings_page.color_green", "Verde"),
            lang_get(L, "settings_page.color_blue", "Azul"),
            lang_get(L, "settings_page.color_pink", "Rosa"),
            lang_get(L, "settings_page.color_yellow", "Amarelo"),
            lang_get(L, "settings_page.color_none", "Sem luz")
        ]
        
        current_text = self.neon_combo.currentText()
        self.neon_combo.blockSignals(True)
        self.neon_combo.clear()
        self.neon_combo.addItems(color_items)
        if current_text in color_items:
            self.neon_combo.setCurrentText(current_text)
        self.neon_combo.blockSignals(False)

        # QComboBox: Temas Especiais
        special_items = [
            lang_get(L, "settings_page.choose_theme", "Nenhum"),
            lang_get(L, "settings_page.theme_christmas", "Natal"),
            lang_get(L, "settings_page.theme_halloween", "Halloween"),
            lang_get(L, "settings_page.theme_easter", "Páscoa"),
            lang_get(L, "settings_page.theme_brazil", "Brasil")
        ]
        current_text = self.special_combo.currentText()
        self.special_combo.blockSignals(True)
        self.special_combo.clear()
        self.special_combo.addItems(special_items)
        if current_text in special_items:
            self.special_combo.setCurrentText(current_text)
        self.special_combo.blockSignals(False)
        
        # QComboBox: Idioma (LISTA MANTIDA FIXA NO IDIOMA BASE - NÃO MUDAR ESTA LISTA!)
        # O nome do idioma atualmente selecionado (ex: "Português") deve ser mantido
        # Não fazemos nada com self.lang_combo aqui, apenas com self.lang_group.setTitle

    # handlers
    def change_theme(self, theme):
        if theme == "light":
            self.parent_window.apply_styles("light")
        else:
            self.parent_window.apply_styles("dark")

    def change_neon_color(self, color_name):
        # Mapeamento estendido para suportar cores nos idiomas traduzidos
        color_map = {
            "Roxo": "#7b4dff", "Viola": "#7b4dff", "Фиолетовый": "#7b4dff", "紫色": "#7b4dff", "보라색": "#7b4dff", "パープル": "#7b4dff", "أرجواني": "#7b4dff", "Lila": "#7b4dff", "Purple": "#7b4dff",
            "Vermelho": "#ff4d4d", "Rosso": "#ff4d4d", "Красный": "#ff4d4d", "红色": "#ff4d4d", "빨간색": "#ff4d4d", "レッド": "#ff4d4d", "أحمر": "#ff4d4d", "Rot": "#ff4d4d", "Red": "#ff4d4d",
            "Verde": "#00ff90", "Verde": "#00ff90", "Зеленый": "#00ff90", "绿色": "#00ff90", "녹색": "#00ff90", "グリーン": "#00ff90", "أخضر": "#00ff90", "Grün": "#00ff90", "Green": "#00ff90",
            "Azul": "#4d90ff", "Blu": "#4d90ff", "Синий": "#4d90ff", "蓝色": "#4d90ff", "파란색": "#4d90ff", "ブルー": "#4d90ff", "أزرق": "#4d90ff", "Blau": "#4d90ff", "Blue": "#4d90ff",
            "Rosa": "#ff4da6", "Rosa": "#ff4da6", "Розовый": "#ff4da6", "粉色": "#ff4da6", "분홍색": "#ff4da6", "ピンク": "#ff4da6", "وردي": "#ff4da6", "Pink": "#ff4da6",
            "Amarelo": "#ffe44d", "Giallo": "#ffe44d", "Желтый": "#ffe44d", "黄色": "#ffe44d", "노란색": "#ffe44d", "イエロー": "#ffe44d", "أصفر": "#ffe44d", "Gelb": "#ffe44d", "Yellow": "#ffe44d",
            "Sem luz": None, "Nessun Effetto Luminoso": None, "Без светового эффекта": None, "无发光效果": None, "빛 효과 없음": None, "光効果なし": None, "بدون تأثير ضوئي": None, "Kein Lichteffekt": None, "No light": None
        }
        color = color_map.get(color_name, NEON_DEFAULT)
        self.parent_window.set_neon_color(color)

    def change_special_theme(self, theme_name):
        self.parent_window.apply_special_theme(theme_name)

    def change_language(self, lang_name):
        # solicita ao parent a troca de idioma
        self.parent_window.apply_language(lang_name)

# ---------------- MainWindow ----------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        # Mapeamento exibido (em PT, fixo) -> código do JSON
        self.supported_languages = {
            "Português": "pt",
            "Inglês": "en",
            "Espanhol": "es",
            "Francês": "fr",
            "Italiano": "it",
            "Alemão": "de",
            "Russo": "ru",
            "Chinês": "zh",
            "Coreano": "ko",
            "Japonês": "ja",
            "Árabe": "ar"
        }

        # carrega idioma padrão (pt) com fallback silencioso
        self.current_lang = load_language_json("pt") or {}

        self.setWindowTitle("Security Toolkit — Neon Dashboard")
        self.resize(1200, 760)
        self._central = QWidget()
        self.setCentralWidget(self._central)

        self.card_widgets = []
        self._build_ui()
        self.apply_styles()  # aplica tema dark por padrão
        self._start_clock()

        self.update_ui_language()

    # ---------- idioma ----------
    def load_language_file(self, lang_code):
        data = load_language_json(lang_code)
        if not data:
            if lang_code != "pt":
                fallback = load_language_json("pt")
                if fallback:
                    return fallback
        return data

    def apply_language(self, lang_name):
        # Como lang_name agora vem da lista fixa, o mapeamento é direto
        if lang_name not in self.supported_languages:
            print(f"Idioma '{lang_name}' não encontrado no mapeamento.")
            return

        lang_code = self.supported_languages[lang_name]
        self.current_lang = self.load_language_file(lang_code) or {}
        self.update_ui_language()

    def update_ui_language(self):
        L = self.current_lang

        # Sidebar
        self.btn_home.setText("  " + (lang_get(L, "home", "Home")))
        self.btn_tools.setText("  " + (lang_get(L, "tools", "Ferramentas")))
        self.btn_scripts.setText("  " + (lang_get(L, "scripts", "Scripts")))
        self.btn_logs.setText("  " + (lang_get(L, "logs", "Logs")))
        self.btn_config.setText("  " + (lang_get(L, "settings", "Configurações")))
        self.btn_exit.setText(lang_get(L, "sidebar.exit", "Sair"))


        # Header
        self.title_label.setText(lang_get(L, "header.operations_panel", "Painel de Operações"))
        self.search.setPlaceholderText(lang_get(L, "header.search_placeholder", "Pesquisar ferramentas..."))
        self.status_label.setText(lang_get(L, "header.status_ready", "Pronto"))

        # Config Page strings (Chama o método na ConfigPage)
        self.config_page.update_ui_language(L)

        # Cards
        card_keys = [
            ("cards.scanner.title", "cards.scanner.subtitle"),
            ("cards.ports.title", "cards.ports.subtitle"),
            ("cards.reports.title", "cards.reports.subtitle"),
            ("cards.scripts_auto.title", "cards.scripts_auto.subtitle"),
            ("cards.targets.title", "cards.targets.subtitle"),
            ("cards.logs.title", "cards.logs.subtitle"),
            ("cards.advanced.title", "cards.advanced.subtitle"),
            ("cards.status.title", "cards.status.subtitle"),
            ("cards.settings.title", "cards.settings.subtitle"),
        ]
        
        fallbacks = [
            ("Scanner de Rede", "Varredura e detecção de hosts"),
            ("Analisador de Portas", "Teste de portas específicas"),
            ("Relatórios", "Geração de CSV/LOG automático"),
            ("Scripts Automáticos", "Execução de rotinas Python/.bat"),
            ("Alvos", "Gerenciar IPs e ranges"),
            ("Logs do Sistema", "Histórico de execuções"),
            ("Modo Avançado", "Funções extras / DevTools"),
            ("Status", "Verificação do ambiente"),
            ("Configurações", "Ajustes do sistema"),
        ]
        
        for i, (tkey, skey) in enumerate(card_keys):
            title = lang_get(L, tkey, fallbacks[i][0])
            subtitle = lang_get(L, skey, fallbacks[i][1])
            
            if i < len(self.card_widgets):
                self.card_widgets[i].set_texts(title, subtitle)

        # Atualiza o título principal da janela
        self.setWindowTitle(lang_get(L, "app_title", "Security Toolkit — Neon Dashboard"))


    # ---------- UI ----------
    def _build_ui(self):
        root = QHBoxLayout()
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)
        self._central.setLayout(root)

        # Sidebar
        sidebar = QWidget()
        sidebar.setObjectName("LeftSidebar")
        sidebar.setFixedWidth(220)
        sb_layout = QVBoxLayout()
        sb_layout.setContentsMargins(12, 12, 12, 12)
        sb_layout.setSpacing(8)
        sidebar.setLayout(sb_layout)

        self.logo = QLabel("Security Toolkit")
        self.logo.setObjectName("logoLabel")
        self.logo.setFixedHeight(40)
        logo_font = QFont()
        logo_font.setPointSize(13)
        logo_font.setBold(True)
        self.logo.setFont(logo_font)
        sb_layout.addWidget(self.logo)

        # Sidebar buttons
        self.btn_home = self._make_sidebar_button("Home", "🏠")
        self.btn_tools = self._make_sidebar_button("Ferramentas", "🛠️")
        self.btn_scripts = self._make_sidebar_button("Scripts", "📜")
        self.btn_logs = self._make_sidebar_button("Logs", "📁")
        self.btn_config = self._make_sidebar_button("Configurações", "⚙️")

        for btn in [self.btn_home, self.btn_tools, self.btn_scripts, self.btn_logs, self.btn_config]:
            sb_layout.addWidget(btn)

        sb_layout.addStretch()

        self.btn_exit = QPushButton("Sair")
        self.btn_exit.clicked.connect(QApplication.instance().quit)
        self.btn_exit.setFixedHeight(36)
        self.btn_exit.setStyleSheet("""
            QPushButton {
                background: #131313;
                border: 2px solid rgba(123,77,255,0.3);
                color: #dbe8ff;
                border-radius: 8px;
            }
            QPushButton:hover {
                background: #1b1b2a;
                border: 2px solid #7b4dff;
                color: #7b4dff;
            }
        """)
        sb_layout.addWidget(self.btn_exit)

        # Main area
        main_area = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(12)
        main_area.setLayout(main_layout)

        # Header
        header = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(8, 8, 8, 8)
        header.setLayout(header_layout)

        self.title_label = QLabel("Painel de Operações")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()

        self.search = QLineEdit()
        self.search.setPlaceholderText("Pesquisar ferramentas...")
        self.search.setFixedWidth(320)
        header_layout.addWidget(self.search)

        self.status_label = QLabel("Pronto")
        header_layout.addWidget(self.status_label)

        self.clock = QLabel("")
        header_layout.addWidget(self.clock)

        main_layout.addWidget(header)

        # Pages
        self.pages = QStackedWidget()
        main_layout.addWidget(self.pages)

        # Home Grid
        home = QWidget()
        grid = QGridLayout()
        grid.setSpacing(14)
        grid.setContentsMargins(6, 6, 6, 6)
        home.setLayout(grid)

        cards = [
            ("🛰️", "Scanner de Rede", "Varredura e detecção de hosts"),
            ("🚪", "Analisador de Portas", "Teste de portas específicas"),
            ("📊", "Relatórios", "Geração de CSV/LOG automático"),
            ("🧪", "Scripts Automáticos", "Execução de rotinas Python/.bat"),
            ("🎯", "Alvos", "Gerenciar IPs e ranges"),
            ("📁", "Logs do Sistema", "Histórico de execuções"),
            ("⚙️", "Modo Avançado", "Funções extras / DevTools"),
            ("📡", "Status", "Verificação do ambiente"),
            ("🔧", "Configurações", "Ajustes do sistema"),
        ]

        pos = [(r, c) for r in range(3) for c in range(3)]
        for i, data in enumerate(cards):
            icon, title, subtitle = data
            card = NeonCard(icon, title, subtitle)
            card.on_card_activated = lambda t=title: self.on_card_activated(t)
            self.card_widgets.append(card)
            r, c = pos[i]
            grid.addWidget(card, r, c)

        self.pages.addWidget(home)

        # Pages placeholders
        tools_page = QLabel("Página Ferramentas - em desenvolvimento")
        tools_page.setAlignment(Qt.AlignmentFlag.AlignCenter)
        scripts_page = QLabel("Página Scripts - em desenvolvimento")
        scripts_page.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logs_page = QLabel("Página Logs - em desenvolvimento")
        logs_page.setAlignment(Qt.AlignmentFlag.AlignCenter)

        # Config Page
        self.config_page = ConfigPage(self)

        self.pages.addWidget(tools_page)
        self.pages.addWidget(scripts_page)
        self.pages.addWidget(logs_page)
        self.pages.addWidget(self.config_page)

        # Connect sidebar
        self.btn_home.clicked.connect(lambda: self.pages.setCurrentIndex(0))
        self.btn_tools.clicked.connect(lambda: self.pages.setCurrentIndex(1))
        self.btn_scripts.clicked.connect(lambda: self.pages.setCurrentIndex(2))
        self.btn_logs.clicked.connect(lambda: self.pages.setCurrentIndex(3))
        self.btn_config.clicked.connect(lambda: self.pages.setCurrentIndex(4))

        root.addWidget(sidebar)
        root.addWidget(main_area)

    def _make_sidebar_button(self, text: str, icon_text: str) -> QToolButton:
        btn = QToolButton()
        btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        btn.setText(f"  {text}")
        btn.setCheckable(True)
        btn.setFixedHeight(44)
        btn.setIconSize(QSize(20, 20))
        btn.setStyleSheet("""
            QToolButton {
                text-align: left; padding-left: 8px; font-size: 13px;
                border: 1px solid #2a2a2a; border-radius: 6px; background: #1b1b1b;
                color: #dbe8ff;
            }
            QToolButton:hover {
                border: 1px solid #7b4dff; background: #232325;
            }
        """)
        return btn

    # === actions ===
    def on_card_activated(self, title: str):
        self.status_label.setText(f"Executando: {title}")
        print(f"[ACTION] Activated: {title}")

    def apply_styles(self, theme="dark"):
        if theme == "light":
            bg_color = BACKGROUND_LIGHT
            card_border = CARD_BORDER_LIGHT
            text_color = "#000000"
        else:
            bg_color = BACKGROUND_DARK
            card_border = CARD_BORDER
            text_color = "#e6eef7"

        qss = f"""
        QWidget {{ background: {bg_color}; color: {text_color}; font-family: 'Segoe UI', Roboto, Arial; }}
        #LeftSidebar {{ background: #0f0f11; border-radius: 8px; }}
        QLabel#logoLabel {{ color: {text_color}; font-weight: 700; font-size: 14px; }}
        QLineEdit {{ background: #0b0b0c; border: 1px solid #232428; padding: 6px; border-radius: 6px; color: {text_color}; }}
        QToolButton {{ color: {text_color}; }}
        QPushButton {{ background: #1b1b1b; color: {text_color}; border-radius: 8px; padding: 6px 10px; }}
        QPushButton:hover {{ background: #232325; }}
        """
        self.setStyleSheet(qss)

    def set_neon_color(self, color):
        for card in self.card_widgets:
            card.set_neon_color(color)

    def apply_special_theme(self, theme_name):
        if theme_name in ["Natal", "Christmas Theme", "Рождественская тема", "圣诞主题", "크리스마스 테마", "クリスマス", "سمة عيد الميلاد", "Weihnachtsthema"]:
            self.setStyleSheet("background-color: #0d0d0d;")
        elif theme_name in ["Halloween", "Halloween Theme", "Тема Хэллоуина", "万圣节主题", "할로윈 테마", "ハロウィン", "سمة الهالوين", "Halloween-Thema"]:
            self.setStyleSheet("background-color: #2a1a00;")
        elif theme_name in ["Páscoa", "Easter Theme", "Пасхальная тема", "复活节主题", "부활절 테마", "イースター", "سمة عيد الفصح", "Osterthema"]:
            self.setStyleSheet("background-color: #f3f0e8;")
        elif theme_name in ["Brasil", "Brazil Theme", "Тема Бразилии", "巴西主题", "브라질 테마", "ブラジル", "سمة البرازيل", "Brasilien-Thema"]:
            self.setStyleSheet("background-color: #009739;")
        else:
            self.apply_styles()

    def _start_clock(self):
        timer = QTimer(self)
        timer.timeout.connect(self._update_time)
        timer.start(1000)
        self._update_time()

    def _update_time(self):
        now = QTime.currentTime().toString("HH:mm:ss")
        self.clock.setText(now)


# ------------------ run ------------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
