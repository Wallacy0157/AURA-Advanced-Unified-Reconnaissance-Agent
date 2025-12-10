# 🌌 AURA — Advanced Unified Reconnaissance Agent

**Dashboard Avançado em Python + PyQt6 para Operações de Segurança Interna**

O **AURA** é um painel moderno e interativo desenvolvido em **PyQt6**, projetado para reunir e gerenciar todas as ferramentas de segurança utilizadas em ambiente interno. Ele centraliza scanners, ferramentas de automação, scripts de análise, verificações de ambiente, relatórios e módulos de configuração.

> ⚠️ **Uso exclusivo para testes autorizados**.
> Não executa atividades maliciosas, não coleta informações sigilosas, não copia dados e não envia nada para fora da rede.
> Toda lógica é 100% focada em **mapear falhas**, **validar controles** e **auxiliar no reforço da segurança**.

---

## ✨ **Recursos Principais**

### 🧭 **Interface Neon Dark Mode**

* Estilo escuro com efeitos neon suaves.
* Cards animados com brilho pulsante (Glow Effect).
* Layout organizado em sidebar + área dinâmica.
* Totalmente escalável a qualquer resolução.

### 🧩 **Módulos Disponíveis no Painel**

Cada card no painel principal representa um sistema do AURA:

* **🛰️ Scanner de Rede** — Varredura e detecção de hosts
* **🚪 Analisador de Portas** — Teste de portas e respostas
* **📊 Relatórios** — Geração de CSV, logs e auditorias
* **🧪 Scripts Automáticos** — Execução de rotinas Python e .bat
* **🎯 Alvos** — Gerenciamento rápido de IPs e ranges
* **📁 Logs do Sistema** — Histórico de execuções
* **⚙️ Modo Avançado** — Funções extras, debug e devtools
* **📡 Status** — Verificação do ambiente
* **🔧 Configurações** — Ajustes gerais

---

## ⚙️ **Configurações Personalizáveis**

### 🎨 **Tema do App**

* Modo **Claro**
* Modo **Escuro** (padrão)

### 🌈 **Cores Neon**

Escolha entre:

* Roxo (padrão)
* Vermelho
* Verde
* Azul
* Rosa
* Amarelo
* Ou totalmente **sem brilho neon**

### 🏷️ **Temas Especiais**

* 🎄 Natal
* 🎃 Halloween
* 🐰 Páscoa
* 🇧🇷 Tema Brasil
* Nenhum (padrão)

### 🌐 **Idiomas do Sistema**

* Português
* Inglês
* Espanhol
* Francês
* Italiano
* Russo
* Chinês
* Coreano
* Japonês
* Alemão
* Árabe

---

## 🧠 **Arquitetura do Projeto**

### Principais classes:

* **NeonCard** → Cards com glow + hover dinâmico.
* **ConfigPage** → Página completa de configurações.
* **MainWindow** → Estrutura principal do dashboard.

### Tecnologias utilizadas:

* **Python 3**
* **PyQt6**
* **Efeitos QSS / QGraphicsDropShadowEffect**
* **QPropertyAnimation** (pulso neon)

---

## ▶️ **Como executar**

```bash
python3 aura_dashboard.py
```

Necessário ter:

* Python 3.9+
* PyQt6 instalado

```bash
pip install PyQt6
```

---

## 📘 **Status do Projeto**

✔ UI Finalizada

✔ Cards funcionais

✔ Configurações ativas

◻ Mais ferramentas internas sendo integradas

---

## 🛡️ Aviso Legal

Este software **não possui** nenhuma funcionalidade voltada para roubo de dados, invasão externa, coleta de informações sigilosas ou qualquer ação ilícita.
É estritamente uma ferramenta de **segurança defensiva**.

---

## 📜 Licença

Uso interno e restrito. Direitos reservados aos autores.
