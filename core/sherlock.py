# core/sherlock.py
import requests
import json
import os
import urllib.parse
from datetime import datetime
from ddgs import DDGS

class SherlockEngine:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
        }
        # Sites para Nicknames
        self.social_sites = {
            "GitHub": "https://github.com/{}",
            "Instagram": "https://www.instagram.com/{}/",
            "X (Twitter)": "https://x.com/{}",
            "Reddit": "https://www.reddit.com/user/{}",
            "LinkedIn (User)": "https://www.linkedin.com/in/{}/"
        }
        # Indexadores para Nomes Reais
        self.people_search_engines = {
            "Webmii": "https://webmii.com/people?n={}",
            "PeekYou": "https://www.peekyou.com/{}",
            "TruePeople": "https://www.truepeoplesearch.com/results?name={}"
        }

    def search_everywhere(self, target, mode="nickname", callback=None):
        """
        mode: "nickname" ou "full_name"
        """
        results = []
        
        if mode == "nickname":
            # 1. Busca Direta (Sherlock Style)
            results.extend(self._direct_search(target, callback))
            # 2. Busca Global e Menções
            results.extend(self._global_search(f'"{target}"', "Nickname Mention", callback))
        else:
            # 3. Busca por Nome Completo (Estilo Webmii/OSINT)
            formatted_name = target.replace(" ", "+")
            results.extend(self._people_search(formatted_name, callback))
            # 4. Busca por Vazamentos e Documentos (Dorking)
            dork_query = f'"{target}" filetype:pdf OR filetype:txt OR filetype:xlsx'
            results.extend(self._global_search(dork_query, "Potential Leak/Doc", callback))
            # 5. Busca em Redes Sociais por Nome
            results.extend(self._global_search(f'site:instagram.com "{target}"', "Social Match", callback))

        # Correlação e Unificação
        unique = {item["url"]: item for item in results}
        return list(unique.values())

    def _direct_search(self, username, callback):
        found = []
        for site, url_form in self.social_sites.items():
            url = url_form.format(username)
            try:
                # Usamos um timeout curto para não travar
                res = requests.get(url, headers=self.headers, timeout=3)
                if res.status_code == 200 and username.lower() in res.text.lower():
                    item = {"site": site, "url": url, "source": "Direct Hit"}
                    found.append(item)
                    if callback: callback(site, url)
            except: continue
        return found

    def _people_search(self, name, callback):
        found = []
        for site, url_form in self.people_search_engines.items():
            url = url_form.format(name)
            # Apenas gera o link, pois muitos People Search bloqueiam scraping simples
            item = {"site": site, "url": url, "source": "Indexador de Pessoas"}
            found.append(item)
            if callback: callback(site, url)
        return found

    def _global_search(self, query, label, callback):
        found = []
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=10)
                for r in results:
                    item = {"site": label, "url": r["href"], "title": r["title"], "source": "Global Search"}
                    found.append(item)
                    if callback: callback(label, r["href"])
        except: pass
        return found

    def save_to_json(self, target, results, base_dir):
        log_dir = os.path.join(base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        filename = f"sherlock_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        path = os.path.join(log_dir, filename)

        data = {
            "target": target,
            "date": datetime.now().isoformat(),
            "total_found": len(results),
            "results": results
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return path

