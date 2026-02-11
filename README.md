# 🌌 AURA — Advanced Unified Reconnaissance Agent

**Security Toolkit em Python + PyQt6 para validações técnicas em ambiente controlado**

O **AURA** é uma aplicação desktop com interface **Neon Dark Mode** construída em **PyQt6**.  
Ele centraliza módulos de **reconhecimento, testes técnicos, auditoria e apoio operacional** em um único painel.

> ⚠️ **Uso educacional e autorizado apenas.**  
> Vários módulos executam ações sensíveis (scanner, força bruta, auditoria de teclado, execução remota, etc.).  
> Utilize somente em laboratórios próprios ou com autorização formal.

---

## ✨ **Recursos Principais**

### 🧭 **Interface Neon Dark Mode**

* Layout em sidebar + área dinâmica (QStackedWidget).
* Cards neon com efeitos visuais (glow / hover).
* Tema claro/escuro com personalização de cor neon.
* Suporte a múltiplos idiomas via JSON.

### 🧩 **Módulos Implementados no Projeto**

Atualmente o código inclui os seguintes módulos/páginas principais:

* **🛰️ Scanner de Rede** — Nmap (`-sV -O --script vuln`) + parsing XML + sugestões (Nikto/SQLMap/Hydra)
* **🧰 Hydra** — Execução de testes de credenciais com opções de usuário/senha/listas e HTTP form
* **💀 John Engine** — Quebra de hash com wordlist/rules/bruteforce (MD5, SHA1, SHA256, SHA512 e BCRYPT quando disponível)
* **🔍 Sherlock / OSINT** — Busca por usernames/nomes em fontes sociais e consulta global
* **⌨️ Key Auditor** — Captura de digitação em arquivo local para auditoria autorizada
* **🛡️ Firewall / Port Check** — Verificação de conectividade de portas
* **🔥 Stress Test** — Teste de carga básico com coleta de evidências em JSON/CSV
* **📦 Payload Builder + Listener** — Geração de agente Python e listener TCP para laboratório

---

## ⚙️ **Configurações Personalizáveis**

### 🎨 **Tema do App**

* **Dark**
* **Light**

### 🌈 **Cor Neon**

* Roxo (padrão)
* Vermelho
* Verde
* Azul
* Rosa
* Amarelo
* Sem efeito neon

### 🌐 **Idiomas Suportados**

* Português
* Inglês
* Espanhol
* Francês
* Italiano
* Alemão
* Russo
* Chinês
* Coreano
* Japonês
* Árabe

---

## 🧠 **Arquitetura (resumo)**

### Arquivo principal

* `security_toolkit.py` — janela principal (`MainWindow`) e páginas de módulo.

### Pasta `core/`

* `components.py` — componentes visuais (`NeonCard`, `ConfigPage`) e internacionalização.
* `config.py` — tema, cor neon e persistência de configurações.
* `network_scanner.py` — varredura Nmap, parse de resultados e integrações web assessment.
* `hydra_engine.py` — worker para Hydra.
* `john_engine.py` — engine de cracking de hash.
* `sherlock.py` — módulo OSINT.
* `logger_engine.py` — motor de auditoria de teclado.
* `stress_test.py` — executor de teste de carga.
* `remote_handler.py` — payload/listerner para ambiente de teste.

### Outras pastas

* `languages/` — traduções da UI.
* `config/user_settings.json` — preferências salvas do usuário.
* `logs/` — relatórios e evidências gerados em runtime.

---

## ▶️ **Como executar**

### 1) Instalar dependências

```bash
pip install -r requirements.txt
```

### 2) Rodar o app

```bash
python3 security_toolkit.py
```

---

## 📦 **Dependências principais**

* PyQt6
* requests
* ddgs
* xmltodict
* passlib
* pynput
* beautifulsoup4
* pytz

Além das libs Python, alguns módulos dependem de ferramentas externas no sistema:

* `nmap`
* `hydra`
* `nikto` (opcional)
* `sqlmap` (opcional)

---

## 📘 **Status do Projeto**

✔ Interface principal funcional  
✔ Persistência de tema/idioma  
✔ Módulos integrados no dashboard  
◻ Evoluções em andamento (organização, hardening e refinos de UX)

---

## 🛡️ Aviso Legal

Este projeto inclui módulos de segurança ofensiva e defensiva para **simulação, validação técnica e estudo**.
O uso indevido é de responsabilidade exclusiva de quem executa.

---

## 📜 Licença

Uso interno / educacional (ajuste conforme política do seu time ou organização).
