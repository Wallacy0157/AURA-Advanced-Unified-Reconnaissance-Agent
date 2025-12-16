# AURA/core/components.py

import json
import os
import sys

from PyQt6.QtCore import Qt, QSize, QThread, pyqtSignal, QTimer, QLocale
from PyQt6.QtGui import QFont, QColor, QPainter, QBrush, QPen, QPalette
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QGraphicsDropShadowEffect, QGroupBox, QRadioButton, 
    QComboBox, QPushButton, QColorDialog,
    QScrollArea 
)

# Importações internas
from core.config import THEMES, NEON_DEFAULT 

# ----------------- 1. Funções de Idioma -----------------
# (Mantido o código load_language_json e lang_get)
def load_language_json(lang_code, base_dir=None):
    """Carrega o arquivo JSON para o código de idioma fornecido."""
    
    if base_dir is None:
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
            
    lang_path = os.path.join(base_dir, "languages", f"{lang_code}.json")
    
    if not os.path.exists(lang_path):
        print(f"[WARN] Arquivo de idioma {lang_code}.json não encontrado em {lang_path}. Usando pt.json como fallback.")
        lang_path = os.path.join(base_dir, "languages", "pt.json")

    try:
        with open(lang_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Falha ao carregar JSON de idioma: {e}. Retornando dicionário vazio.")
        return {}

def lang_get(L: dict, key: str, fallback: str):
    """Obtém um valor traduzido usando uma chave pontilhada (ex: 'sidebar.home')."""
    parts = key.split('.')
    value = L
    for part in parts:
        value = value.get(part)
        if value is None:
            return fallback
    return value if isinstance(value, str) else fallback

# ----------------- 2. Componentes de UI -----------------

class NeonCard(QFrame):
    """Um QFrame estilizado com sombra e cor neon personalizável."""
    # ⚠️ CORREÇÃO: Mudar 'icon_text' para 'icon'
    def __init__(self, icon, title, subtitle, neon_color, theme_manager, parent=None): 
        super().__init__(parent)
        self.neon_color = neon_color
        self.theme_manager = theme_manager
        
        self.current_theme_key = theme_manager.current_theme 

        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setFrameShadow(QFrame.Shadow.Raised)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedSize(QSize(280, 160))
        self.setObjectName("NeonCard") 
        
        self.effect = QGraphicsDropShadowEffect(self)
        self._apply_shadow()

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 15, 20, 15)
        self.layout.setSpacing(8)

        # Icone
        # ⚠️ CORREÇÃO: Usar 'icon' (o novo nome do argumento)
        self.icon_label = QLabel(icon) 
        self.icon_label.setFont(QFont("Arial", 28))
        self.layout.addWidget(self.icon_label)

        # Título
        self.title_label = QLabel(title)
        self.title_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        self.layout.addWidget(self.title_label)
        
        # Subtítulo
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setFont(QFont("Arial", 10))
        self.subtitle_label.setWordWrap(True)
        self.layout.addWidget(self.subtitle_label)
        
        self.layout.addStretch()
        
        self.on_card_activated = lambda: None
        
        self.on_card_activated = lambda: None 

    def mousePressEvent(self, event):
        """Trata o clique de forma segura para o PyQt6."""
        # Verifica se foi o botão esquerdo
        if event.button() == Qt.MouseButton.LeftButton:
            # Só executa se houver algo conectado
            if self.on_card_activated:
                self.on_card_activated()
        
        # Aceita o evento para que ele não cause instabilidade no SIP
        event.accept()

    def _get_style_sheet(self, theme_key):
    # (Código mantido)
        T = THEMES.get(theme_key, THEMES['dark'])
        return f"""
            QFrame#NeonCard {{
                background-color: {T['bg_card']};
                border: 2px solid {self.neon_color}; 
                border-radius: 12px;
            }}
            QFrame#NeonCard:hover {{
                background-color: {T['bg_card']};
                border: 2px solid {T['text_main']}; 
            }}
            QFrame#NeonCard QLabel {{
                color: {T['text_main']};
            }}
            QFrame#NeonCard QLabel:last-child {{ 
                color: {T['text_secondary']};
            }}
        """

    def _apply_shadow(self):
    # (Código mantido)
        self.effect.setBlurRadius(18)
        self.effect.setColor(QColor(self.neon_color))
        self.effect.setOffset(0, 0)
        self.setGraphicsEffect(self.effect)
        
    def set_neon_color(self, color, theme_key):
    # (Código mantido)
        self.neon_color = color
        self.current_theme_key = theme_key
        
        self._apply_shadow() 
        self.setStyleSheet(self._get_style_sheet(theme_key))

    def set_texts(self, title, subtitle):
    # (Código mantido)
        self.title_label.setText(title)
        self.subtitle_label.setText(subtitle)
        
# ----------------- 3. Página de Configuração -----------------

class ConfigPage(QWidget):
# (Todo o restante do código da ConfigPage é mantido)
    LANGUAGE_MAP_REVERSE = {
        "pt": "Português", "en": "Inglês", "es": "Espanhol", 
        "fr": "Francês", "de": "Alemão", "it": "Italiano",
        "ru": "Russo", "zh": "Chinês", "ko": "Coreano", 
        "ja": "Japonês", "ar": "Árabe"
    }

    def __init__(self, parent_window):
        super().__init__()
        self.parent_window = parent_window
        
        self.L = parent_window.L 
        
        self._setup_ui()
        self._initialize_values()

    def _setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)

        self.scroll_area = QScrollArea() 
        self.scroll_area.setWidgetResizable(True)
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)
        content_layout.setSpacing(20)
        
        # --- Grupo 1: Idioma ---
        self.lang_group = QGroupBox(lang_get(self.L, "settings_page.lang_group", "Idioma"))
        self.lang_group.setObjectName("lang_group")
        lang_layout = QHBoxLayout()
        
        self.lang_combo = QComboBox()
        combo_items = list(self.LANGUAGE_MAP_REVERSE.values()) 
        self.lang_combo.addItems(combo_items)

        self.lang_combo.currentTextChanged.connect(self.change_language)
        lang_layout.addWidget(self.lang_combo)
        self.lang_group.setLayout(lang_layout)
        content_layout.addWidget(self.lang_group)

        # --- Grupo 2: Tema Base ---
        self.theme_group = QGroupBox(lang_get(self.L, "settings_page.theme_group", "Tema da Interface"))
        self.theme_group.setObjectName("theme_group")
        theme_layout = QHBoxLayout()
        self.radio_dark = QRadioButton(lang_get(self.L, "settings_page.theme_dark", "Escuro"))
        self.radio_light = QRadioButton(lang_get(self.L, "settings_page.theme_light", "Claro"))
        
        self.radio_dark.toggled.connect(lambda: self.change_theme('dark'))
        self.radio_light.toggled.connect(lambda: self.change_theme('light'))

        theme_layout.addWidget(self.radio_dark)
        theme_layout.addWidget(self.radio_light)
        theme_layout.addStretch()
        self.theme_group.setLayout(theme_layout)
        content_layout.addWidget(self.theme_group)

        # --- Grupo 3: Cor Neon ---
        self.neon_group = QGroupBox(lang_get(self.L, "settings_page.neon_group", "Cor Neon (Cards)"))
        self.neon_group.setObjectName("neon_group")
        neon_layout = QHBoxLayout()
        
        self.color_display = QFrame()
        self.color_display.setFixedSize(QSize(30, 30))
        self.color_display.setStyleSheet(f"background-color: {self.parent_window.theme_manager.neon_color}; border: 1px solid white; border-radius: 15px;")
        
        self.color_button = QPushButton(lang_get(self.L, "settings_page.pick_color", "Escolher Cor"))
        self.color_button.clicked.connect(self.pick_neon_color)
        
        self.reset_button = QPushButton(lang_get(self.L, "settings_page.reset_color", "Restaurar Padrão"))
        self.reset_button.clicked.connect(self.reset_neon_color)
        
        neon_layout.addWidget(self.color_display)
        neon_layout.addWidget(self.color_button)
        neon_layout.addWidget(self.reset_button)
        neon_layout.addStretch()
        self.neon_group.setLayout(neon_layout)
        content_layout.addWidget(self.neon_group)
        
        content_layout.addStretch()
        self.scroll_area.setWidget(content_widget)
        layout.addWidget(self.scroll_area)
        self.setLayout(layout)

    def _initialize_values(self):
        """Define os valores iniciais dos widgets com base nas configurações salvas."""
        
        # Idioma
        current_lang = self.parent_window.current_lang_code
        lang_name = self.LANGUAGE_MAP_REVERSE.get(current_lang, "Português")
        index = self.lang_combo.findText(lang_name)
        if index != -1:
            self.lang_combo.currentTextChanged.disconnect()
            self.lang_combo.setCurrentIndex(index)
            self.lang_combo.currentTextChanged.connect(self.change_language)
            
        # Tema Base
        current_theme = self.parent_window.theme_manager.current_theme
        if current_theme == 'dark':
            self.radio_dark.setChecked(True)
        else:
            self.radio_light.setChecked(True)
            
        # Cor Neon
        current_neon = self.parent_window.theme_manager.neon_color
        self.color_display.setStyleSheet(f"background-color: {current_neon}; border: 1px solid white; border-radius: 15px;")


    def update_ui_language(self, L):
        """Atualiza todos os textos da página de configurações quando o idioma muda."""
        self.L = L 
        
        # GroupBox Titles
        self.findChild(QGroupBox, "lang_group").setTitle(lang_get(L, "settings_page.lang_group", "Idioma"))
        self.findChild(QGroupBox, "theme_group").setTitle(lang_get(L, "settings_page.theme_group", "Tema da Interface"))
        self.findChild(QGroupBox, "neon_group").setTitle(lang_get(L, "settings_page.neon_group", "Cor Neon (Cards)"))
        
        # Botões/Labels
        self.radio_dark.setText(lang_get(L, "settings_page.theme_dark", "Escuro"))
        self.radio_light.setText(lang_get(L, "settings_page.theme_light", "Claro"))
        self.color_button.setText(lang_get(L, "settings_page.pick_color", "Escolher Cor"))
        self.reset_button.setText(lang_get(L, "settings_page.reset_color", "Restaurar Padrão"))
        
        current_lang_code = self.parent_window.current_lang_code
        lang_name = self.LANGUAGE_MAP_REVERSE.get(current_lang_code, "Português")
        index = self.lang_combo.findText(lang_name)
        if index != -1:
            self.lang_combo.setCurrentIndex(index)

    # --- Slots ---
    
    def change_language(self, lang_name):
        self.parent_window.apply_language(lang_name)
        
    def change_theme(self, theme_key):
        if theme_key == 'dark' and self.radio_dark.isChecked():
            self.parent_window.apply_base_theme('dark')
        elif theme_key == 'light' and self.radio_light.isChecked():
            self.parent_window.apply_base_theme('light')

    def pick_neon_color(self):
        current_color = QColor(self.parent_window.theme_manager.neon_color)
        color = QColorDialog.getColor(current_color, self, lang_get(self.L, "settings_page.dialog_title", "Escolher Cor Neon"))
        
        if color.isValid():
            hex_color = color.name().lower()
            self.color_display.setStyleSheet(f"background-color: {hex_color}; border: 1px solid white; border-radius: 15px;")
            self.parent_window.set_global_neon_color(hex_color)
            
    def reset_neon_color(self):
        self.color_display.setStyleSheet(f"background-color: {NEON_DEFAULT}; border: 1px solid white; border-radius: 15px;")
        self.parent_window.set_global_neon_color(NEON_DEFAULT)
