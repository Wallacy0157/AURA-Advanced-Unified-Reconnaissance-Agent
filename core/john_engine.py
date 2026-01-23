# core/john_engine.py
import hashlib
import os
import time
import json
from datetime import datetime
from multiprocessing import Pool, cpu_count, Manager
import itertools
import string

# ==========================================================
# ⚙️ Worker multiprocessing
# ==========================================================
def worker(args):
    word, target_hash, algorithm, salt, use_rules, stop_event = args

    # 🔒 Sanitização obrigatória
    word = (
        word.replace("\ufeff", "")
            .replace("\r", "")
            .replace("\n", "")
            .strip()
    )

    if not word or stop_event.is_set():
        return None

    algo_map = {
        "MD5": hashlib.md5,
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512
    }

    algo_func = algo_map.get(algorithm)
    if not algo_func:
        return None

    variants = {word}
    if use_rules:
        variants |= {
            word.lower(),
            word.upper(),
            word.capitalize(),
            word[::-1],
            word + "123",
            word + "!",
            "!" + word
        }

    modes = ("suffix", "prefix") if salt else ("suffix",)

    for variant in variants:
        for mode in modes:
            if stop_event.is_set():
                return None

            if salt:
                test = salt + variant if mode == "prefix" else variant + salt
            else:
                test = variant

            if algo_func(test.encode()).hexdigest().lower() == target_hash:
                stop_event.set()
                return variant

    return None


class JohnEngine:
    def __init__(self):
        self.algorithms = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
            "SHA512": hashlib.sha512
        }

        self.hash_length_map = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512"
        }

        self.mask_map = {
            "?l": string.ascii_lowercase,
            "?u": string.ascii_uppercase,
            "?d": string.digits,
            "?s": "!@#$%^&*()"
        }

    # ==========================================================
    # 🔍 Detecta algoritmo pelo tamanho do hash
    # ==========================================================
    def detect_algorithm(self, target_hash):
        return self.hash_length_map.get(len(target_hash))

    # ==========================================================
    # 🔥 Crack usando wordlist
    # ==========================================================
    def crack_wordlist(
        self,
        target_hash,
        wordlist_path,
        algorithm=None,
        salt=None,
        use_rules=False,
        callback=None,
        processes=None
    ):
        target_hash = target_hash.strip().lower()

        if not algorithm:
            algorithm = self.detect_algorithm(target_hash)
            if not algorithm:
                return {"success": False, "error": "Algoritmo não identificado"}

        processes = processes or cpu_count()
        start = time.time()
        tested = 0

        with Manager() as manager:
            stop_event = manager.Event()

            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = [line for line in f]

            args = [
                (w, target_hash, algorithm, salt, use_rules, stop_event)
                for w in words
            ]

            with Pool(processes) as pool:
                for result in pool.imap_unordered(worker, args, chunksize=100):
                    tested += 1

                    if callback and tested % 100 == 0:
                        elapsed = time.time() - start
                        speed = int(tested / elapsed) if elapsed > 0 else 0
                        callback(tested, speed)

                    if result:
                        pool.terminate()
                        return {
                            "success": True,
                            "password": result,
                            "hash": target_hash,
                            "algorithm": algorithm,
                            "salt": salt
                        }

        return {"success": False, "error": "Senha não encontrada"}

    # ==========================================================
    # 🔥 Crack usando máscara
    # ==========================================================
    def crack_mask(
        self,
        target_hash,
        mask,
        algorithm=None,
        salt=None,
        callback=None,
        processes=None
    ):
        target_hash = target_hash.strip().lower()

        if not algorithm:
            algorithm = self.detect_algorithm(target_hash)
            if not algorithm:
                return {"success": False, "error": "Algoritmo não identificado"}

        processes = processes or cpu_count()
        start = time.time()
        tested = 0

        candidates = list(self.expand_mask(mask))

        with Manager() as manager:
            stop_event = manager.Event()

            args = [
                (w, target_hash, algorithm, salt, False, stop_event)
                for w in candidates
            ]

            with Pool(processes) as pool:
                for result in pool.imap_unordered(worker, args, chunksize=500):
                    tested += 1

                    if callback and tested % 100 == 0:
                        elapsed = time.time() - start
                        speed = int(tested / elapsed) if elapsed > 0 else 0
                        callback(tested, speed)

                    if result:
                        pool.terminate()
                        return {
                            "success": True,
                            "password": result,
                            "hash": target_hash,
                            "algorithm": algorithm,
                            "salt": salt
                        }

        return {"success": False, "error": "Senha não encontrada"}

    # ==========================================================
    # 🎭 Expansão de máscara (?l?l?d)
    # ==========================================================
    def expand_mask(self, mask):
        pools = []
        i = 0
        while i < len(mask):
            token = mask[i:i + 2]
            if token in self.mask_map:
                pools.append(self.mask_map[token])
                i += 2
            else:
                pools.append(mask[i])
                i += 1

        return ("".join(p) for p in itertools.product(*pools))

    # ==========================================================
    # 📊 Benchmark real (H/s)
    # ==========================================================
    def benchmark(self, algorithm, duration=5):
        algo_func = self.algorithms.get(algorithm)
        if not algo_func:
            return None

        start = time.time()
        count = 0

        while time.time() - start < duration:
            algo_func(b"benchmark").hexdigest()
            count += 1

        return int(count / duration)

    # ==========================================================
    # 💾 Salva o resultado em JSON
    # ==========================================================
    def save_result(self, result, base_dir):
        log_dir = os.path.join(base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        agora = datetime.now()

        report_data = {
            "relatorio_tipo": "Quebra de Hash - Auditoria de Segurança",
            "gerado_por": "AURA Advanced Unit",
            "data_execucao": agora.strftime("%d/%m/%Y %H:%M:%S"),
            "status": "SUCESSO" if result.get("success") else "FALHA",
            "detalhes": {
                "hash_alvo": result.get("hash"),
                "algoritmo": result.get("algorithm"),
                "salt_utilizado": result.get("salt"),
                "senha_descoberta": result.get("password") if result.get("success") else "N/A"
            },
            "timestamp_unix": time.time()
        }

        filename = f"john_crack_{agora.strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(log_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

        return filepath

