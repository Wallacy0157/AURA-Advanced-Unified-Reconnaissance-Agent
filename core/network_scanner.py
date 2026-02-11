import subprocess
import xmltodict
import json
import os
import pytz
import shutil
from datetime import datetime

NMAP_BASE_CMD = [
    "nmap",
    "-sV",
    "-O",
    "--script", "vuln",
    "-oX", "-"
]

def classify_services(open_ports):
    profile = {
        "web": False,
        "database": False,
        "remote_access": False,
        "auth_service": False
    }

    for p in open_ports:
        service = p.get("service", "").lower()

        if service in ["http", "https"]:
            profile["web"] = True

        if service in ["mysql", "postgresql", "mssql", "oracle"]:
            profile["database"] = True

        if service in ["ssh", "ftp", "telnet", "rdp"]:
            profile["remote_access"] = True
            profile["auth_service"] = True

    return profile


def suggest_next_steps(service_profile):
    suggestions = []

    if service_profile.get("web"):
        suggestions.append("nikto")

    if service_profile.get("database"):
        suggestions.append("sqlmap")

    if service_profile.get("auth_service"):
        suggestions.append("hydra")

    return suggestions


def scan_network_target(ip_list: list):
    all_results = []

    for ip in ip_list:
        ip = ip.strip()
        if not ip:
            continue

        print(f"[*] Scanning {ip} with Nmap...")

        cmd = build_nmap_command(ip)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutos por host
            )

            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip())

            data_dict = xmltodict.parse(result.stdout)
            parsed_hosts = parse_hosts(data_dict)
            all_results.extend(parsed_hosts)

        except subprocess.TimeoutExpired:
            print(f"[!] Timeout scanning {ip}")
            all_results.append({
                "ip": ip,
                "error": "Scan timeout"
            })

        except Exception as e:
            print(f"[ERRO] {ip}: {e}")
            all_results.append({
                "ip": ip,
                "error": str(e)
            })

    return all_results

def scan_single_target(ip: str):
    results = scan_network_target([ip])

    if results:
        return results[0]

    return {
        "ip": ip,
        "error": "Nenhum resultado retornado"
    }


def parse_hosts(data):
    results = []
    hosts = data.get("nmaprun", {}).get("host", [])

    if isinstance(hosts, dict):
        hosts = [hosts]

    for host in hosts:
        info = {
            "ip": extract_ip(host),
            "os": extract_os(host),
            "open_ports": extract_ports(host)
        }

        info["service_profile"] = classify_services(info["open_ports"])
        info["suggested_tests"] = suggest_next_steps(info["service_profile"])
        info["vulnerabilities"] = extract_vulnerabilities(host)
        # Web assessment
        info["web_assessment"] = {}

        urls = detect_web_urls(info["ip"], info["open_ports"])

        if urls:
            info["web_assessment"]["detected_urls"] = urls

            # Nikto
            info["web_assessment"]["nikto"] = []
            for url in urls:
                info["web_assessment"]["nikto"].append({
                    "url": url,
                    "result": run_nikto(url)
                })

            # SQLMap
            info["web_assessment"]["sqlmap"] = []
            for url in urls:
                info["web_assessment"]["sqlmap"].append({
                    "url": url,
                    "result": run_sqlmap(url)
                })

        results.append(info)

    return results

def extract_ip(host):
    addresses = host.get("address", [])
    if isinstance(addresses, dict):
        addresses = [addresses]

    for addr in addresses:
        if addr.get("@addrtype") == "ipv4":
            return addr.get("@addr")

    return "N/A"

def extract_os(host):
    os_data = host.get("os", {}).get("osmatch")
    if isinstance(os_data, list):
        return os_data[0].get("@name", "Unknown")
    if isinstance(os_data, dict):
        return os_data.get("@name", "Unknown")
    return "Unknown"

def extract_ports(host):
    ports_data = host.get("ports", {}).get("port", [])
    if isinstance(ports_data, dict):
        ports_data = [ports_data]

    open_ports = []

    for port in ports_data:
        if port.get("state", {}).get("@state") != "open":
            continue

        service = port.get("service", {}).get("@name", "").lower()
        if service in ["tcpwrapped", "tcpwrapper"]:
            continue

        open_ports.append({
            "port": port.get("@portid"),
            "protocol": port.get("@protocol"),
            "service": service
        })

    return open_ports

def detect_web_urls(ip, open_ports):
    urls = []

    for p in open_ports:
        if p["service"] == "http":
            urls.append(f"http://{ip}:{p['port']}")
        elif p["service"] == "https":
            urls.append(f"https://{ip}:{p['port']}")

    return urls

def run_nikto(url):
    if not shutil.which("nikto"):
        return {"error": "Nikto não está instalado"}

    print(f"[+] Rodando Nikto em {url}...")

    try:
        result = subprocess.run(
            ["nikto", "-h", url],
            capture_output=True,
            text=True,
            timeout=600
        )

        return {
            "status": "executed",
            "output": result.stdout[:8000]  # evita relatório gigante
        }

    except subprocess.TimeoutExpired:
        return {"error": "Nikto timeout"}

def run_sqlmap(url):
    if not shutil.which("sqlmap"):
        return {"error": "SQLMap não está instalado"}

    print(f"[+] Preparando SQLMap para {url}...")

    cmd = [
        "sqlmap",
        "-u", url,
        "--batch",
        "--level=1",
        "--risk=1",
        "--crawl=1"
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=900
        )

        return {
            "status": "executed",
            "output": result.stdout[:8000]
        }

    except subprocess.TimeoutExpired:
        return {"error": "SQLMap timeout"}

def extract_vulnerabilities(host):
    vulns = []
    ports = host.get("ports", {}).get("port", [])
    if isinstance(ports, dict):
        ports = [ports]

    for port in ports:
        scripts = port.get("script", [])
        if isinstance(scripts, dict):
            scripts = [scripts]

        for script in scripts:
            output = script.get("@output", "")
            if any(keyword in output.upper() for keyword in ["VULNERABLE", "CVE-", "EXPLOIT"]):
                vulns.append({
                    "port": port.get("@portid"),
                    "script": script.get("@id"),
                    "details": output
                })

    return vulns

def parse_vulners_output(vulners_data: dict, port: int):
    vulns = []

    for vuln_id, vuln_data in vulners_data.items():
        vulns.append({
            "cve": vuln_id if vuln_id.startswith("CVE") else None,
            "cvss": vuln_data.get("cvss"),
            "source": "vulners",
            "url": vuln_data.get("href"),
            "port": port,
            "exploit_available": vuln_data.get("exploit", False)
        })

    return vulns


def build_nmap_command(ip):
    cmd = ["nmap", "-sV", "--script", "vuln", "-oX", "-"]

    if os.geteuid() == 0:
        cmd.insert(1, "-O")  # OS scan só se root
    else:
        print("[!] Rodando sem OS detection (sem privilégios)")

    cmd.append(ip)
    return cmd

def save_json(results, filename):
    tz = pytz.timezone("America/Sao_Paulo")
    now = datetime.now(tz)

    report = {
        "scan_metadata": {
            "tool": "AURA - Advanced Unified Reconnaissance Agent",
            "scan_date": now.strftime("%Y-%m-%d"),
            "scan_time": now.strftime("%H:%M:%S"),
            "timezone": "America/Sao_Paulo"
        },
        "results": results
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

def is_root():
    return os.geteuid() == 0


