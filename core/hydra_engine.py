import subprocess
import shutil
import json
from datetime import datetime

from PyQt6.QtCore import QObject, pyqtSignal


class HydraWorker(QObject):
    output_line = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal(int)

    def __init__(
        self,
        targets,
        service,
        username,
        password,
        user_list,
        pass_list,
        port,
        tasks,
        stop_on_success,
        verbose,
        targets_file=None,
        http_path=None,
        http_params=None,
        http_fail=None,
    ):
        super().__init__()

        # Alvos
        self.targets = targets
        self.targets_file = targets_file

        # Serviço
        self.service = service

        # Credenciais
        self.username = username
        self.password = password
        self.user_list = user_list
        self.pass_list = pass_list

        # Opções
        self.port = port
        self.tasks = tasks
        self.stop_on_success = stop_on_success
        self.verbose = verbose

        # HTTP POST FORM
        self.http_path = http_path
        self.http_params = http_params
        self.http_fail = http_fail

        # Controle
        self.process = None
        self._stop_requested = False

    # ===============================
    # STOP SEGURO
    # ===============================
    def stop(self):
        self._stop_requested = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass

    # ===============================
    # MONTAGEM DO COMANDO
    # ===============================
    def _build_command(self):
        cmd = ["hydra", "-I"]

        if self.tasks:
            cmd.extend(["-t", str(self.tasks)])

        if self.stop_on_success:
            cmd.append("-f")

        if self.verbose:
            cmd.append("-V")

        if self.port:
            cmd.extend(["-s", str(self.port)])

        if self.user_list:
            cmd.extend(["-L", self.user_list])
        elif self.username:
            cmd.extend(["-l", self.username])

        if self.pass_list:
            cmd.extend(["-P", self.pass_list])
        elif self.password:
            cmd.extend(["-p", self.password])

        # Alvos
        if self.targets_file:
            cmd.extend(["-M", self.targets_file])
        else:
            cmd.append(self.targets[0])

        # Serviço
        if self.service == "http-post-form":
            form = f"{self.http_path}:{self.http_params}:{self.http_fail}"
            cmd.append("http-post-form")
            cmd.append(form)
        else:
            cmd.append(self.service)

        return cmd

    # ===============================
    # EXECUÇÃO (THREAD)
    # ===============================
    def start(self):
        if not shutil.which("hydra"):
            self.error.emit("Hydra não encontrado no PATH.")
            self.finished.emit(127)
            return

        cmd = self._build_command()
        self.output_line.emit(f"[INFO] Executando: {' '.join(cmd)}")

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            for line in self.process.stdout:
                if self._stop_requested:
                    self.output_line.emit("[INFO] Ataque interrompido pelo usuário.")
                    break
                self.output_line.emit(line.rstrip())

            if self._stop_requested and self.process.poll() is None:
                self.process.terminate()

            return_code = self.process.wait()
            self.finished.emit(return_code)

        except Exception as exc:
            self.error.emit(f"Erro ao executar Hydra: {exc}")
            self.finished.emit(1)

