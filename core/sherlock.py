# core/sherlock.py
import requests
import json
import os
from datetime import datetime

class SherlockEngine:
    def __init__(self):
        self.sites = {
            "GitHub": "https://github.com/{}",
            "Instagram": "https://www.instagram.com/{}/",
            "Twitter (X)": "https://twitter.com/{}",
            "TikTok": "https://www.tiktok.com/@{}",
            "Reddit": "https://www.reddit.com/user/{}",
            "YouTube": "https://www.youtube.com/@{}",
            "Steam": "https://steamcommunity.com/id/{}",
            "Pinterest": "https://www.pinterest.com/{}",
            "Twitch": "https://www.twitch.com/{}",
            "Spotify": "https://open.spotify.com/user/{}",
            "Letterboxd": "https://letterboxd.com/{}/"
        }

    def search_user(self, username, callback):
        found_results = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        
        for site, url in self.sites.items():
            target_url = url.format(username)
            try:
                response = requests.get(target_url, headers=headers, timeout=5)
                if response.status_code == 200:
                    if "not found" not in response.text.lower():
                        found_results.append({"site": site, "url": target_url})
                        callback(site, target_url)
            except:
                continue
        return found_results

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
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        return filepath
