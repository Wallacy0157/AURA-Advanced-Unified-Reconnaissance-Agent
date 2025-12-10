# NEO — Network Exploration Operator

Ferramenta em Python desenvolvida para auxiliar em atividades de auditoria interna, permitindo a execução de rotinas de varredura, testes e automações de forma prática e rastreável.

Feita para uso em **ambiente Linux**, com **ambiente virtual (venv)** e dependências específicas para cada módulo.  
Utilize somente em sistemas nos quais você possui autorização.

---

## ✨ Recursos principais

- Execução automatizada de rotinas de segurança  
- Varredura de múltiplos hosts  
- Registro detalhado de falhas, sucessos e motivos  
- Geração de relatórios em **JSON** ou **CSV**  
- Execução modular: você pode adicionar / remover módulos facilmente  
- Logs completos com opção `--verbose`  
- Salvamento automático em casos de interrupção (Ctrl+C)  
- Estruturado para rodar via **cron**, **systemd** ou manualmente  

---

## 📁 Estrutura recomendada do projeto

\`\`\`
neo/
│
├── neo.py                   # Script principal
├── modules/                 # Pasta com módulos (scan, ssh, http, etc)
│   ├── scanner.py
│   ├── reporter.py
│   └── ...
│
├── config/
│   └── hosts.txt            # Lista de IPs/hosts
│
├── output/
│   ├── resultados.json
│   └── resultados.csv
│
├── README.md
└── venv/                    # Ambiente virtual
\`\`\`

---

## 🔧 Instalação (Linux)

### 1) Criar ambiente virtual
\`\`\`bash
python3 -m venv venv
\`\`\`

### 2) Ativar o venv
\`\`\`bash
source venv/bin/activate
\`\`\`

### 3) (Opcional) atualizar pip
\`\`\`bash
python -m pip install --upgrade pip
\`\`\`

### 4) Instalar dependências
Exemplo (ajuste conforme seus módulos):
\`\`\`bash
pip install paramiko
pip install python-nmap
\`\`\`

---

## ▶️ Como executar

Execução padrão:
\`\`\`bash
python neo.py --verbose
\`\`\`

Usando arquivo customizado de hosts:
\`\`\`bash
python neo.py --hosts config/hosts.txt --verbose
\`\`\`

Selecionar formato de saída:
\`\`\`bash
python neo.py --output output/resultado.json --format json --verbose
python neo.py --output output/resultado.csv --format csv
\`\`\`

Executar como root mantendo o venv:
\`\`\`bash
sudo venv/bin/python neo.py --verbose
\`\`\`

---

## 📦 Formato de relatório (JSON)

\`\`\`json
{
  "host": "172.16.0.10",
  "acesso": true,
  "modulos_executados": ["ssh_test", "port_scan"],
  "tentativas": [
    {
      "modulo": "ssh_test",
      "usuario": "root",
      "senha": "root",
      "acesso": true,
      "detalhes": "comando remoto executado",
      "tempo_segundos": 0.52
    }
  ]
}
\`\`\`

---

## ⏹ Interromper com segurança

Para parar:
\`\`\`bash
Ctrl + C
\`\`\`

O script salva automaticamente os resultados parciais no arquivo de saída escolhido.

---

## ✔️ Conclusão

NEO é uma ferramenta modular, eficiente e organizada para auditoria de sistemas internos.
