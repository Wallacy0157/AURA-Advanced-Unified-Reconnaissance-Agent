#!/usr/bin/env python3
"""
Security Toolkit - PyQt6 Dark Neon Dashboard com Configurações

Inclui:
- Página de Configurações (tema, neon color, temas especiais, idiomas)
- Glow pulsante nos cards
- Layout moderno baseado na versão aprovada
"""

import sys
from PyQt6.QtCore import Qt, QTimer, QTime, QSize, QPropertyAnimation
from PyQt6.QtGui import QIcon, QFont, QColor
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QHBoxLayout, QVBoxLayout,
    QGridLayout, QToolButton, QPushButton, QStackedWidget, QFrame,
    QSizePolicy, QLineEdit, QGraphicsDropShadowEffect, QGroupBox, QRadioButton,
    QComboBox, QSpacerItem
)

NEON_DEFAULT = "#7b4dff"
BACKGROUND_DARK = "#0d0d0d"
BACKGROUND_LIGHT = "#f5f5f5"
CARD_BG = "#131313"
CARD_BORDER = "#2a2a2a"
CARD_BORDER_LIGHT = "#d3d3d3"

# === Neon Card ===
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
        title_label = QLabel(self.title)
        title_label.setObjectName("cardTitle")
        title_label.setWordWrap(True)
        subtitle_label = QLabel(self.subtitle)
        subtitle_label.setObjectName("cardSubtitle")

        text_col.addWidget(title_label)
        text_col.addWidget(subtitle_label)
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
        self.neon_color = color if color else "#00000000"
        self.shadow.setColor(QColor(self.neon_color))
        self.setStyleSheet(self.base_stylesheet())

# === Config Page ===
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
        theme_group = QGroupBox("Tema do App")
        theme_layout = QHBoxLayout()
        self.light_theme_btn = QRadioButton("Claro")
        self.dark_theme_btn = QRadioButton("Escuro")
        self.dark_theme_btn.setChecked(True)
        theme_layout.addWidget(self.light_theme_btn)
        theme_layout.addWidget(self.dark_theme_btn)
        theme_group.setLayout(theme_layout)
        layout.addWidget(theme_group)
        self.light_theme_btn.toggled.connect(lambda: self.change_theme("light"))
        self.dark_theme_btn.toggled.connect(lambda: self.change_theme("dark"))

        # Cor Neon
        neon_group = QGroupBox("Cor dos Cards")
        neon_layout = QHBoxLayout()
        self.neon_combo = QComboBox()
        self.neon_combo.addItems(["Roxo", "Vermelho", "Verde", "Azul", "Rosa", "Amarelo", "Sem luz"])
        neon_layout.addWidget(self.neon_combo)
        neon_group.setLayout(neon_layout)
        layout.addWidget(neon_group)
        self.neon_combo.currentTextChanged.connect(self.change_neon_color)

        # Temas especiais
        special_group = QGroupBox("Temas Especiais")
        special_layout = QHBoxLayout()
        self.special_combo = QComboBox()
        self.special_combo.addItems(["Nenhum", "Natal", "Halloween", "Páscoa", "Brasil"])
        special_layout.addWidget(self.special_combo)
        special_group.setLayout(special_layout)
        layout.addWidget(special_group)
        self.special_combo.currentTextChanged.connect(self.change_special_theme)

        # Idioma
        lang_group = QGroupBox("Idioma da Interface")
        lang_layout = QHBoxLayout()
        self.lang_combo = QComboBox()
        self.lang_combo.addItems([
            "Português", "Inglês", "Espanhol", "Francês", "Italiano",
            "Russo", "Chinês", "Coreano", "Japonês", "Alemão", "Árabe"
        ])
        lang_layout.addWidget(self.lang_combo)
        lang_group.setLayout(lang_layout)
        layout.addWidget(lang_group)
        self.lang_combo.currentTextChanged.connect(self.change_language)

        layout.addStretch()
        self.setLayout(layout)

    # === Funções para mudanças dinâmicas ===
    def change_theme(self, theme):
        if theme == "light":
            self.parent_window.apply_styles("light")
        else:
            self.parent_window.apply_styles("dark")

    def change_neon_color(self, color_name):
        color_map = {
            "Roxo": "#7b4dff",
            "Vermelho": "#ff4d4d",
            "Verde": "#00ff90",
            "Azul": "#4d90ff",
            "Rosa": "#ff4da6",
            "Amarelo": "#ffe44d",
            "Sem luz": None
        }
        color = color_map[color_name]
        self.parent_window.set_neon_color(color)

    def change_special_theme(self, theme_name):
        self.parent_window.apply_special_theme(theme_name)

    def change_language(self, lang_name):
        self.parent_window.apply_language(lang_name)

# === Main Window ===
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Toolkit — Neon Dashboard")
        self.resize(1200, 760)
        self._central = QWidget()
        self.setCentralWidget(self._central)
        self.card_widgets = []
        self._build_ui()
        self.apply_styles()
        self._start_clock()

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

        logo = QLabel("Security Toolkit")
        logo.setObjectName("logoLabel")
        logo.setFixedHeight(40)
        logo_font = QFont()
        logo_font.setPointSize(13)
        logo_font.setBold(True)
        logo.setFont(logo_font)
        sb_layout.addWidget(logo)

        # Sidebar buttons
        self.btn_home = self._make_sidebar_button("Home", "🏠")
        self.btn_tools = self._make_sidebar_button("Ferramentas", "🛠️")
        self.btn_scripts = self._make_sidebar_button("Scripts", "📜")
        self.btn_logs = self._make_sidebar_button("Logs", "📁")
        self.btn_config = self._make_sidebar_button("Configurações", "⚙️")

        for btn in [self.btn_home, self.btn_tools, self.btn_scripts, self.btn_logs, self.btn_config]:
            sb_layout.addWidget(btn)

        sb_layout.addStretch()

        exit_btn = QPushButton("Sair")
        exit_btn.clicked.connect(QApplication.instance().quit)
        exit_btn.setFixedHeight(36)
        sb_layout.addWidget(exit_btn)

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

        # Pages placeholder
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

    # === Funções de ação ===
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
        # exemplo simples para cores de fundo
        if theme_name == "Natal":
            self.setStyleSheet("background-color: #0d0d0d;")
        elif theme_name == "Halloween":
            self.setStyleSheet("background-color: #2a1a00;")
        elif theme_name == "Páscoa":
            self.setStyleSheet("background-color: #f3f0e8;")
        elif theme_name == "Brasil":
            self.setStyleSheet("background-color: #009739;")
        else:
            self.apply_styles()

    def apply_language(self, lang_name):
        # Placeholder: trocar textos
        print(f"Idioma selecionado: {lang_name}")

    def _start_clock(self):
        timer = QTimer(self)
        timer.timeout.connect(self._update_time)
        timer.start(1000)
        self._update_time()

    def _update_time(self):
        now = QTime.currentTime().toString("HH:mm:ss")
        self.clock.setText(now)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

