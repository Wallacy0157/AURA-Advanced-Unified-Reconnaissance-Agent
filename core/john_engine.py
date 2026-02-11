# core/john_engine.py
import hashlib
import os
import time
import json
from datetime import datetime
from multiprocessing import Pool, cpu_count, Manager
import itertools
import string
import warnings

# ==========================================================
# 🔕 Silencia avisos chatos do passlib
# ==========================================================
warnings.filterwarnings("ignore", category=UserWarning)

# ==========================================================
# 🔐 BCRYPT (opcional)
# ==========================================================
try:
    from passlib.hash import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

# ==========================================================
# ⚙️ Worker multiprocessing (FORA da classe)
# ==========================================================
def worker(args):
    word, target_hash, algorithm, salt, use_rules, stop_event = args

    if stop_event.is_set():
        return None

    # 🧼 Sanitização forte
    word = (
        word.replace("\ufeff", "")
            .replace("\r", "")
            .replace("\n", "")
            .strip()
    )

    if not word:
        return None

    # =======================
    # 🔐 BCRYPT
    # =======================
    if algorithm == "BCRYPT":
        if not HAS_BCRYPT:
            return None
        try:
            if bcrypt.verify(word, target_hash):
                stop_event.set()
                return word
        except Exception:
            return None
        return None

    # =======================
    # 🔑 HASHLIB
    # =======================
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

    for variant in variants:
        if stop_event.is_set():
            return None

        test = variant + salt if salt else variant
        digest = algo_func(test.encode()).hexdigest().lower()

        if digest == target_hash:
            stop_event.set()
            return variant

    return None


# ==========================================================
# 🧠 JohnEngine
# ==========================================================
class JohnEngine:
    def __init__(self):
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
    # 🔍 Detecta algoritmo
    # ==========================================================
    def detect_algorithm(self, target_hash):
        target_hash = target_hash.strip()

        if target_hash.startswith(("$2a$", "$2b$", "$2y$")):
            return "BCRYPT"

        return self.hash_length_map.get(len(target_hash))

    # ==========================================================
    # 🔥 Crack Wordlist
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

        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                words = f.readlines()
        except Exception as e:
            return {"success": False, "error": str(e)}

        processes = processes or cpu_count()
        tested = 0
        start = time.time()

        with Manager() as manager:
            stop_event = manager.Event()

            args = [
                (w, target_hash, algorithm, salt, use_rules, stop_event)
                for w in words
            ]

            with Pool(processes) as pool:
                chunksize = 1 if algorithm == "BCRYPT" else 100

                for result in pool.imap_unordered(worker, args, chunksize):
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
    # 🎭 Expansão de máscara
    # ==========================================================
    def expand_mask(self, mask):
        pools = []
        i = 0
        while i < len(mask):
            token = mask[i:i+2]
            if token in self.mask_map:
                pools.append(self.mask_map[token])
                i += 2
            else:
                pools.append(mask[i])
                i += 1
        return ("".join(p) for p in itertools.product(*pools))

    # ==========================================================
    # 💾 Salvar resultado
    # ==========================================================
    def save_result(self, result, base_dir):
        log_dir = os.path.join(base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        now = datetime.now()

        data = {
            "status": "SUCESSO" if result.get("success") else "FALHA",
            "hash": result.get("hash"),
            "algoritmo": result.get("algorithm"),
            "senha": result.get("password"),
            "data": now.strftime("%d/%m/%Y %H:%M:%S")
        }

        path = os.path.join(
            log_dir,
            f"john_result_{now.strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return path

