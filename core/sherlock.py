# core/sherlock.py
import requests
import json
import os
from datetime import datetime
from duckduckgo_search import DDGS


class SherlockEngine:
    def __init__(self):
        self.sites = {
            "GitHub": {
                "url": "https://github.com/{}",
                "error_text": "Not Found"
            },
            "Instagram": {
                "url": "https://www.instagram.com/{}/",
                "error_text": "Sorry, this page isn't available"
            },
            "X (Twitter)": {
                "url": "https://x.com/{}",
                "error_text": "This account doesn’t exist"
            },
            "TikTok": {
                "url": "https://www.tiktok.com/@{}",
                "error_text": "Couldn't find this account"
            },
            "Reddit": {
                "url": "https://www.reddit.com/user/{}",
                "error_text": "Sorry, nobody on Reddit goes by that name"
            },
            "YouTube": {
                "url": "https://www.youtube.com/@{}",
                "error_text": "This page isn't available"
            },
            "Steam": {
                "url": "https://steamcommunity.com/id/{}",
                "error_text": "The specified profile could not be found"
            },
            "Pinterest": {
                "url": "https://www.pinterest.com/{}/",
                "error_text": "Sorry! We couldn’t find that page"
            },
            "Twitch": {
                "url": "https://www.twitch.tv/{}",
                "error_text": "Sorry. Unless you’ve got a time machine"
            },
            "Spotify": {
                "url": "https://open.spotify.com/user/{}",
                "error_text": "Page not available"
            },
            "Letterboxd": {
                "url": "https://letterboxd.com/{}/",
                "error_text": "Sorry, we can’t find the page"
            }
        }

        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

    # 🔍 Busca em sites conhecidos
    def search_user(self, username, callback=None):
        found_results = []

        for site, data in self.sites.items():
            target_url = data["url"].format(username)

            try:
                response = requests.get(
                    target_url,
                    headers=self.headers,
                    timeout=5,
                    allow_redirects=True
                )

                if response.status_code == 200:
                    if data["error_text"].lower() not in response.text.lower():
                        result = {
                            "site": site,
                            "url": target_url,
                            "source": "direct"
                        }
                        found_results.append(result)

                        if callback:
                            callback(site, target_url)

            except requests.RequestException:
                continue

        return found_results

    # 🌍 Busca global via DuckDuckGo (Versão Corrigida)
    def search_duckduckgo(self, username, max_results=15, callback=None):
        found_results = []
        query = f'"{username}"'
        
        try:
            with DDGS() as ddgs:
                results = ddgs.text(query, max_results=max_results)
                for r in results:
                    url = r.get("href")
                    title = r.get("title")
                    if url:
                        result = {"site": "DuckDuckGo", "title": title, "url": url, "source": "search"}
                        found_results.append(result)
                        if callback:
                            callback("DuckDuckGo", url)
        except Exception as e:
            print(f"Erro no DuckDuckGo: {e}")
            
        return found_results

    # 🔥 Busca completa (Chama o motor novo)
    def search_everywhere(self, username, callback=None):
        results = []
        results.extend(self.search_user(username, callback))
        results.extend(self.search_duckduckgo(username, callback=callback))
        
        unique = {item["url"]: item for item in results}
        return list(unique.values())

    # 💾 Salvar resultado
    def save_to_json(self, username, results, base_dir):
        log_dir = os.path.join(base_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        filename = f"sherlock_{username}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(log_dir, filename)

        data = {
            "username": username,
            "date": datetime.now().isoformat(),
            "total_found": len(results),
            "results": results
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        return filepath

