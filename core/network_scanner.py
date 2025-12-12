# AURA/core/network_scanner.py

import subprocess
import xmltodict
import json
import os
import tempfile
import re

# Esta função rodará o Nmap para uma lista de IPs
def scan_network_target(ip_list: list):
    all_results = []
    
    for ip in ip_list:
        ip = ip.strip()
        if not ip:
            continue
            
        print(f"[*] Rodando Nmap em {ip}...")
        
        # O Nmap precisa de privilégios de root para usar -sV e outras opções avançadas
        cmd = [
            "sudo", "nmap", "-A", "-sV", "--script", "vuln", "-oX", "-", ip
        ]
        
        try:
            # Roda o comando e captura a saída XML diretamente (stdout)
            # Removemos a necessidade de arquivo temporário
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,  # Levanta erro se o Nmap falhar
                encoding='utf-8'
            )
            
            xml_output = result.stdout
            
            # 1. Converte XML para Dicionário Python
            data_dict = xmltodict.parse(xml_output)
            
            # 2. Extrai informações relevantes
            filtered_data = extract_relevant_info(data_dict)
            
            all_results.extend(filtered_data)

        except subprocess.CalledProcessError as e:
            error_message = f"Erro ao rodar Nmap em {ip}: {e.stderr.strip()}"
            print(f"[ERRO] {error_message}")
            all_results.append({"ip": ip, "error": error_message})
        except Exception as e:
            error_message = f"Erro de processamento para {ip}: {e}"
            print(f"[ERRO] {error_message}")
            all_results.append({"ip": ip, "error": error_message})
            
    return all_results

def extract_relevant_info(data):
    # Sua função extract_relevant_info permanece aqui
    result = []
    hosts = data.get("nmaprun", {}).get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    for host in hosts:
        info = {}
        addr = host.get("address", {})
        if isinstance(addr, list):
            for a in addr:
                if a.get("@addrtype") == "ipv4":
                    info["ip"] = a.get("@addr")
        elif isinstance(addr, dict) and addr.get("@addrtype") == "ipv4":
            info["ip"] = addr.get("@addr")
        else:
             info["ip"] = "N/A"

        os_data = host.get("os")
        osmatch = None
        if os_data:
            osmatch = os_data.get("osmatch")
        if osmatch:
            if isinstance(osmatch, list):
                info["os"] = osmatch[0].get("@name")
            else:
                info["os"] = osmatch.get("@name")
        else:
            info["os"] = "Desconhecido"

        ports_info = []
        ports = host.get("ports", {}).get("port", [])
        if isinstance(ports, dict):
            ports = [ports]
        for port in ports:
            # Garante que só porta aberta é considerada
            if port.get("state", {}).get("@state") == "open":
                ports_info.append({
                    "port": port.get("@portid"),
                    "protocol": port.get("@protocol"),
                    "service": port.get("service", {}).get("@name", "-")
                })
        info["open_ports"] = ports_info

        vulns = []
        for port in ports:
            scripts = port.get("script", [])
            if isinstance(scripts, dict):
                scripts = [scripts]
            for script in scripts:
                output = script.get("@output", "")
                if "VULNERABLE" in output.upper():
                    vulns.append(output)
        info["vulnerabilities"] = vulns

        result.append(info)

    return result

# Funções auxiliares (opcional, para testes rápidos do módulo)
def save_json(data, filename="scan_result.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[*] Arquivo JSON salvo em: {filename}")

if __name__ == "__main__":
    # Exemplo de uso para teste
    # ATENÇÃO: É necessário rodar com sudo para que o Nmap funcione corretamente
    print("Teste rápido do scanner (pode precisar de sudo para rodar o Nmap).")
    test_ips = ["127.0.0.1"]
    results = scan_network_target(test_ips)
    save_json(results)
