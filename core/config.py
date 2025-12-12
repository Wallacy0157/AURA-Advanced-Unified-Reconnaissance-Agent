# AURA/core/config.py

import json
import os

# ----------------- Cores e Constantes -----------------
NEON_DEFAULT = "#7b4dff" # Cor neon padrão (roxa)

# Dicionários de Cores para Temas Padrão
THEMES = {
    "dark": {
        "bg_main": "#0d0d0d",
        "bg_sidebar": "#0f0f11",
        "bg_card": "#131313",
        "text_main": "#e6eef7",
        "text_secondary": "#9aa7b8",
        "border_card": "#2a2a2a",
        "bg_search": "#0b0b0c",
        "border_search": "#232428",
        "bg_button": "#1b1b1b",
        "bg_button_hover": "#232325",
        "bg_input": "#1b1b1b",
    },
    "light": {
        "bg_main": "#f5f5f5",
        "bg_sidebar": "#e0e0e0",
        "bg_card": "#ffffff",
        "text_main": "#1a1a1a",
        "text_secondary": "#5c5c5c",
        "border_card": "#d3d3d3",
        "bg_search": "#ffffff",
        "border_search": "#cccccc",
        "bg_button": "#e9e9e9",
        "bg_button_hover": "#dedede",
        "bg_input": "#ffffff",
    },
}

# ⚠️ Os SPECIAL_THEMES e as constantes de temas especiais foram removidos.

# ----------------- Classe de Gerenciamento de Tema (SIMPLIFICADA) -----------------
class ThemeManager:
    """
    Gerencia o estado atual do tema base (dark/light) e a cor neon.
    A lógica de temas especiais foi removida.
    """
    def __init__(self, initial_settings):
        self.current_theme = initial_settings.get("theme", "dark")
        self.neon_color = initial_settings.get("neon_color", NEON_DEFAULT)

    def set_base_theme(self, theme_key):
        """Define o tema base (dark/light)."""
        self.current_theme = theme_key

    def set_neon_color(self, color):
        """Define a cor neon dos cards e do título AURA."""
        self.neon_color = color
        
# ----------------- Funções de Persistência -----------------
def load_user_settings(base_dir):
    """Carrega as configurações do usuário do user_settings.json."""
    settings_path = os.path.join(base_dir, "config", "user_settings.json")
    default_settings = {
        "language": "pt", 
        "theme": "dark",
        "neon_color": NEON_DEFAULT,
        # ⚠️ As chaves de tema especial foram removidas do padrão.
    }
    
    os.makedirs(os.path.dirname(settings_path), exist_ok=True)
    
    if os.path.exists(settings_path):
        try:
            with open(settings_path, "r", encoding="utf-8") as f:
                settings = json.load(f)
                
                # ⚠️ Remove chaves antigas de temas especiais se existirem no arquivo
                settings.pop("special_theme_active", None)
                settings.pop("special_theme_key", None)
                
                return {**default_settings, **settings} 
        except (json.JSONDecodeError, IOError):
            print("[WARN] Erro ao carregar user_settings.json. Usando padrão.")
            
    return default_settings

def save_user_settings(base_dir, settings):
    """Salva as configurações do usuário no user_settings.json."""
    # ⚠️ Garantimos que as chaves de tema especial não sejam salvas
    settings_to_save = {k: v for k, v in settings.items() if k not in ["special_theme_active", "special_theme_key"]}
    
    settings_path = os.path.join(base_dir, "config", "user_settings.json")
    try:
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings_to_save, f, indent=4, ensure_ascii=False)
    except IOError as e:
        print(f"[ERROR] Falha ao salvar user_settings.json: {e}")
