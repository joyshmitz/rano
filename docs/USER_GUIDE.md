# rano User Guide

## Огляд

**rano** (Rust Agent Network Observer) - інструмент моніторингу мережевих з'єднань від AI CLI процесів (Claude Code, Codex CLI, Gemini CLI).

### Що робить rano

- Відстежує вихідні TCP/UDP з'єднання від AI CLI та їх subprocess'ів
- Атрибуція провайдерів (Anthropic, OpenAI, Google)
- Логування подій в SQLite
- Real-time статистика в терміналі
- Алерти на підозрілу активність

### Як працює

rano опитує `/proc` filesystem для mapping'у сокетів до PID:

```
/proc/net/tcp → inode → /proc/{pid}/fd → PID → process info
```

---

## Підтримувані платформи

| Платформа | Live моніторинг | Report/Export | Config |
|-----------|-----------------|---------------|--------|
| Linux x86_64 | ✅ | ✅ | ✅ |
| Linux aarch64 | ✅ | ✅ | ✅ |
| macOS x86_64 | ❌ | ✅ | ✅ |
| macOS aarch64 | ❌ | ✅ | ✅ |
| Windows x86_64 | ❌ | ✅ | ✅ |

**Примітка:** Live моніторинг потребує `/proc` filesystem, який доступний тільки на Linux.

---

## Встановлення

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash
```

### З вихідного коду

```bash
git clone https://github.com/Dicklesworthstone/rano
cd rano
cargo build --release
cp target/release/rano ~/.local/bin/
```

### Перевірка

```bash
rano --version
rano --help
```

---

## Linux: Повна функціональність

### Базовий моніторинг

```bash
# Моніторинг дефолтних AI CLI (claude, codex, gemini)
rano

# Конкретний процес
rano --pattern claude

# Конкретний PID
rano --pid 1234

# PID без subprocess'ів
rano --pid 1234 --no-descendants

# Один poll і вихід
rano --once
```

### Domain Attribution

rano підтримує два режими резолвінгу доменів:

| Режим | Привілеї | Точність | Опис |
|-------|----------|----------|------|
| PTR (default) | Не потрібні | Середня | Reverse DNS lookup |
| pcap | root/CAP_NET_RAW | Висока | DNS response + TLS SNI parsing |

```bash
# PTR режим (default)
rano --domain-mode ptr

# Pcap режим (потребує root)
sudo rano --domain-mode pcap

# Або з capabilities
sudo setcap cap_net_raw+ep $(which rano)
rano --domain-mode pcap
```

### Алерти

```bash
# Алерт на підозрілі домени
rano --alert-domain "*.suspicious.com"

# Алерт на перевищення кількості з'єднань
rano --alert-max-connections 100

# Алерт на з'єднання до невідомих доменів
rano --alert-unknown-domain

# Алерт з terminal bell
rano --alert-bell

# Комбінація
rano --pattern claude \
  --alert-domain "*.cn" \
  --alert-domain "*.ru" \
  --alert-max-connections 50 \
  --alert-unknown-domain \
  --alert-bell
```

### Логування

```bash
# SQLite (default: observer.sqlite)
rano --sqlite /var/log/rano/ai-monitor.sqlite

# JSON log file
rano --json --log-file /var/log/rano/events.jsonl

# Per-session log files
rano --log-dir /var/log/rano/sessions --log-format json
```

### Presets

```bash
# Список доступних
rano --list-presets

# Використання
rano --preset audit      # Аудит: мінімум шуму, все логується
rano --preset quiet      # Тихий: мінімум виводу
rano --preset live       # Live: часті stats
rano --preset verbose    # Verbose: максимум деталей

# Комбінація (пізніший перевизначає)
rano --preset audit --preset verbose
```

### Фонове виконання

```bash
# Systemd service
sudo tee /etc/systemd/system/rano.service << 'EOF'
[Unit]
Description=rano AI CLI Network Observer
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rano --pattern claude --pattern codex --pattern gemini --sqlite /var/log/rano/observer.sqlite --log-dir /var/log/rano/sessions
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now rano
```

---

## macOS: Обмежена функціональність

На macOS відсутній `/proc` filesystem, тому live моніторинг не працює.

### Що працює

| Функція | Статус |
|---------|--------|
| `rano report` | ✅ Звіти з SQLite |
| `rano export` | ✅ Експорт CSV/JSONL |
| `rano config` | ✅ Валідація конфігу |
| `rano --list-presets` | ✅ Список пресетів |
| `rano update` | ✅ Оновлення |
| Live monitoring | ❌ Потребує /proc |

### Workflow на macOS

1. **Моніторинг на Linux** (server, VM, container)
2. **Копіювання SQLite** на macOS
3. **Аналіз** за допомогою report/export

```bash
# На Linux
rano --sqlite /tmp/session.sqlite

# Копіювання на macOS
scp linux-server:/tmp/session.sqlite ~/analysis/

# Аналіз на macOS
rano report --latest --sqlite ~/analysis/session.sqlite
rano export --format csv --sqlite ~/analysis/session.sqlite > report.csv
```

### Альтернатива: Linux VM

```bash
# UTM / Parallels / Docker
docker run -it --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --pid=host \
  --net=host \
  ubuntu:latest bash -c "
    apt-get update && apt-get install -y curl
    curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash
    rano --pattern claude
  "
```

---

## Конфігурація

### Структура файлів

```
~/.config/rano/
├── config.conf          # Основні налаштування (key=value)
├── rano.toml            # Кастомізація провайдерів (TOML)
└── presets/             # Кастомні пресети
    └── mypreset.conf

~/project/
└── rano.toml            # Проєктні налаштування
```

### Пріоритет

```
CLI args > ENV vars > ./rano.toml > ~/.config/rano/* > defaults
```

### config.conf

```ini
# ~/.config/rano/config.conf

# Процеси
pattern=claude,codex,gemini
exclude_pattern=browser

# Polling
interval_ms=1000

# Output
color=auto
theme=vivid
json=false
summary_only=false

# SQLite
sqlite=/var/log/rano/observer.sqlite
db_batch_size=200
db_flush_ms=1000
db_queue_max=10000

# Stats
stats_interval_ms=2000
stats_top=5
stats_view=provider

# Network
include_udp=true
include_listening=false
no_dns=false
```

### rano.toml

```toml
# ~/.config/rano/rano.toml

[providers]
mode = "merge"  # або "replace"

# Додаткові патерни
anthropic = ["claude-code", "claude-desktop"]
openai = ["chatgpt", "gpt-cli"]
google = ["bard", "aistudio"]
```

### Валідація

```bash
rano config check   # Перевірка помилок
rano config show    # Показати resolved config
rano config paths   # Показати шляхи до файлів
```

---

## Reports та Export

### Reports

```bash
# Останній session
rano report --latest

# За часом
rano report --since 24h
rano report --since 7d
rano report --since 2026-01-20
rano report --since 2026-01-20T10:00:00Z

# Діапазон
rano report --since 2026-01-20 --until 2026-01-21

# JSON output
rano report --latest --json

# Кастомна база
rano report --latest --sqlite /path/to/db.sqlite
```

### Export

```bash
# CSV (Excel-compatible)
rano export --format csv > connections.csv
rano export --format csv --no-header > data.csv

# JSONL (для jq)
rano export --format jsonl > events.jsonl

# Фільтри
rano export --format csv --provider anthropic
rano export --format csv --domain "*.openai.com"
rano export --format csv --since 24h
rano export --format csv --run-id "session-123"
```

### Аналіз з jq

```bash
# Унікальні домени
rano export --format jsonl | jq -r '.domain' | sort -u

# Кількість по провайдерах
rano export --format jsonl | jq -r '.provider' | sort | uniq -c

# Топ IP адреси
rano export --format jsonl | jq -r '.remote_ip' | sort | uniq -c | sort -rn | head -10

# Фільтр по provider
rano export --format jsonl | jq 'select(.provider == "anthropic")'
```

---

## Інтеграція з Netdata

[Netdata](https://www.netdata.cloud/) - система моніторингу з real-time візуалізацією. rano можна інтегрувати через custom charts.d.plugin.

### Принцип

1. rano експортує метрики в SQLite
2. Bash скрипт читає метрики з SQLite
3. charts.d.plugin передає дані в Netdata

### Встановлення плагіну

```bash
# Створити плагін
sudo tee /usr/libexec/netdata/charts.d/rano.chart.sh << 'EOF'
# rano.chart.sh - Netdata charts.d.plugin for rano
# Reference: https://learn.netdata.cloud/docs/developer-and-contributor-corner/external-plugins/charts.d.plugin

# shellcheck shell=bash

# Configuration
rano_db="${RANO_DB:-/var/log/rano/observer.sqlite}"
rano_update_every=10

rano_check() {
    # Перевірка наявності sqlite3
    require_cmd sqlite3 || return 1

    # Перевірка наявності бази даних
    [ -f "$rano_db" ] || return 1

    return 0
}

rano_create() {
    # Chart: Connections by provider
    cat << CHART
CHART rano.providers '' 'AI CLI Connections by Provider' 'connections' rano rano.providers stacked 1000 $rano_update_every
DIMENSION anthropic '' absolute 1 1
DIMENSION openai '' absolute 1 1
DIMENSION google '' absolute 1 1
DIMENSION unknown '' absolute 1 1
CHART

    # Chart: Active connections
    cat << CHART
CHART rano.active '' 'AI CLI Active Connections' 'connections' rano rano.active line 1001 $rano_update_every
DIMENSION active '' absolute 1 1
DIMENSION peak '' absolute 1 1
CHART

    # Chart: Events rate
    cat << CHART
CHART rano.events '' 'AI CLI Connection Events' 'events/s' rano rano.events line 1002 $rano_update_every
DIMENSION connects '' incremental 1 1
DIMENSION closes '' incremental 1 1
CHART

    return 0
}

rano_update() {
    # $1 = microseconds since last update

    # Query provider counts
    local data
    data=$(sqlite3 -separator ' ' "$rano_db" "
        SELECT
            COALESCE(SUM(CASE WHEN provider='anthropic' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN provider='openai' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN provider='google' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN provider='unknown' THEN 1 ELSE 0 END), 0)
        FROM events
        WHERE ts > datetime('now', '-1 hour');
    " 2>/dev/null)

    local anthropic openai google unknown
    read -r anthropic openai google unknown <<< "$data"

    # Query active connections (connect without matching close)
    local active
    active=$(sqlite3 "$rano_db" "
        SELECT COUNT(*) FROM events e1
        WHERE e1.event = 'connect'
        AND NOT EXISTS (
            SELECT 1 FROM events e2
            WHERE e2.event = 'close'
            AND e2.local_port = e1.local_port
            AND e2.ts > e1.ts
        )
        AND e1.ts > datetime('now', '-1 hour');
    " 2>/dev/null)

    # Query event counts
    local connects closes
    connects=$(sqlite3 "$rano_db" "SELECT COUNT(*) FROM events WHERE event='connect';" 2>/dev/null)
    closes=$(sqlite3 "$rano_db" "SELECT COUNT(*) FROM events WHERE event='close';" 2>/dev/null)

    # Output data
    cat << DATA
BEGIN rano.providers
SET anthropic = ${anthropic:-0}
SET openai = ${openai:-0}
SET google = ${google:-0}
SET unknown = ${unknown:-0}
END
BEGIN rano.active
SET active = ${active:-0}
SET peak = ${active:-0}
END
BEGIN rano.events
SET connects = ${connects:-0}
SET closes = ${closes:-0}
END
DATA

    return 0
}
EOF

# Зробити виконуваним
sudo chmod +x /usr/libexec/netdata/charts.d/rano.chart.sh
```

### Конфігурація

```bash
# /etc/netdata/charts.d/rano.conf
rano_db="/var/log/rano/observer.sqlite"
rano_update_every=10
```

### Активація

```bash
# Редагувати charts.d.conf
sudo tee -a /etc/netdata/charts.d.conf << 'EOF'
rano=yes
EOF

# Перезапустити netdata
sudo systemctl restart netdata
```

### Перевірка

```bash
# Debug mode
/usr/libexec/netdata/plugins.d/charts.d.plugin debug 1 rano

# Web UI
# http://localhost:19999 → Charts → rano
```

### Grafana Dashboard

Netdata інтегрується з Grafana через [Netdata datasource plugin](https://grafana.com/grafana/plugins/netdatacloud-netdata-datasource/).

---

## Інтеграція з Prometheus + Grafana

[Prometheus](https://prometheus.io/) - система моніторингу з time-series database. [Grafana](https://grafana.com/) - платформа візуалізації.

### Архітектура

```
rano → SQLite → cron script → textfile → Node Exporter → Prometheus → Grafana
```

### Метод 1: Node Exporter Textfile Collector

Рекомендований підхід - використовувати [Node Exporter textfile collector](https://github.com/prometheus/node_exporter#textfile-collector).

#### Скрипт експорту метрик

```bash
# /usr/local/bin/rano-prometheus.sh
#!/bin/bash
# rano metrics exporter for Prometheus Node Exporter textfile collector
# Reference: https://prometheus.io/docs/instrumenting/writing_exporters/

set -euo pipefail

RANO_DB="${RANO_DB:-/var/log/rano/observer.sqlite}"
OUTPUT_DIR="${TEXTFILE_COLLECTOR_DIR:-/var/lib/node_exporter/textfile_collector}"
OUTPUT_FILE="${OUTPUT_DIR}/rano.prom"
TEMP_FILE="${OUTPUT_FILE}.tmp"

# Перевірка наявності бази
if [ ! -f "$RANO_DB" ]; then
    echo "# HELP rano_up rano database availability" > "$TEMP_FILE"
    echo "# TYPE rano_up gauge" >> "$TEMP_FILE"
    echo "rano_up 0" >> "$TEMP_FILE"
    mv "$TEMP_FILE" "$OUTPUT_FILE"
    exit 0
fi

# Запит метрик з SQLite
read -r anthropic openai google unknown <<< $(sqlite3 -separator ' ' "$RANO_DB" "
    SELECT
        COALESCE(SUM(CASE WHEN provider='anthropic' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN provider='openai' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN provider='google' THEN 1 ELSE 0 END), 0),
        COALESCE(SUM(CASE WHEN provider='unknown' THEN 1 ELSE 0 END), 0)
    FROM events
    WHERE ts > datetime('now', '-1 hour');
" 2>/dev/null || echo "0 0 0 0")

connects=$(sqlite3 "$RANO_DB" "SELECT COUNT(*) FROM events WHERE event='connect';" 2>/dev/null || echo "0")
closes=$(sqlite3 "$RANO_DB" "SELECT COUNT(*) FROM events WHERE event='close';" 2>/dev/null || echo "0")
alerts=$(sqlite3 "$RANO_DB" "SELECT COUNT(*) FROM events WHERE alert=1;" 2>/dev/null || echo "0")

# Генерація метрик у форматі Prometheus
cat > "$TEMP_FILE" << EOF
# HELP rano_up rano database availability
# TYPE rano_up gauge
rano_up 1

# HELP rano_connections_total Total connections by provider (last hour)
# TYPE rano_connections_total gauge
rano_connections_total{provider="anthropic"} ${anthropic:-0}
rano_connections_total{provider="openai"} ${openai:-0}
rano_connections_total{provider="google"} ${google:-0}
rano_connections_total{provider="unknown"} ${unknown:-0}

# HELP rano_events_total Total events by type
# TYPE rano_events_total counter
rano_events_total{event="connect"} ${connects:-0}
rano_events_total{event="close"} ${closes:-0}

# HELP rano_alerts_total Total alerts triggered
# TYPE rano_alerts_total counter
rano_alerts_total ${alerts:-0}

# HELP rano_scrape_timestamp_seconds Unix timestamp of last scrape
# TYPE rano_scrape_timestamp_seconds gauge
rano_scrape_timestamp_seconds $(date +%s)
EOF

# Атомарне оновлення файлу
mv "$TEMP_FILE" "$OUTPUT_FILE"
```

#### Встановлення

```bash
# Створити скрипт
sudo tee /usr/local/bin/rano-prometheus.sh << 'SCRIPT'
# ... (вміст скрипта вище)
SCRIPT

sudo chmod +x /usr/local/bin/rano-prometheus.sh

# Створити директорію для textfile collector
sudo mkdir -p /var/lib/node_exporter/textfile_collector

# Cron job (кожні 30 секунд)
sudo tee /etc/cron.d/rano-prometheus << 'EOF'
* * * * * root /usr/local/bin/rano-prometheus.sh
* * * * * root sleep 30 && /usr/local/bin/rano-prometheus.sh
EOF
```

#### Конфігурація Node Exporter

```bash
# /etc/default/prometheus-node-exporter
ARGS="--collector.textfile.directory=/var/lib/node_exporter/textfile_collector"
```

```bash
# Перезапуск
sudo systemctl restart prometheus-node-exporter
```

#### Перевірка

```bash
# Локально
cat /var/lib/node_exporter/textfile_collector/rano.prom

# Через Node Exporter
curl -s http://localhost:9100/metrics | grep rano_
```

### Метод 2: Script Exporter

Використання [script_exporter](https://github.com/ricoberger/script_exporter) для виконання скриптів по запиту від Prometheus.

#### Конфігурація script_exporter

```yaml
# /etc/script_exporter/config.yaml
scripts:
  - name: rano
    command: /usr/local/bin/rano-metrics.sh
    timeout: 10s
```

#### Скрипт метрик

```bash
# /usr/local/bin/rano-metrics.sh
#!/bin/bash
RANO_DB="${RANO_DB:-/var/log/rano/observer.sqlite}"

if [ ! -f "$RANO_DB" ]; then
    echo "rano_up 0"
    exit 0
fi

echo "rano_up 1"

sqlite3 "$RANO_DB" "
    SELECT 'rano_connections_total{provider=\"' || provider || '\"} ' || COUNT(*)
    FROM events
    WHERE ts > datetime('now', '-1 hour')
    GROUP BY provider;
" 2>/dev/null
```

#### Prometheus scrape config

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: 'rano'
    metrics_path: /probe
    params:
      script: [rano]
    static_configs:
      - targets: ['localhost:9469']
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: localhost:9469
```

### Grafana Dashboard

#### Імпорт JSON

```json
{
  "title": "rano - AI CLI Network Monitor",
  "panels": [
    {
      "title": "Connections by Provider",
      "type": "piechart",
      "targets": [
        {
          "expr": "rano_connections_total",
          "legendFormat": "{{provider}}"
        }
      ]
    },
    {
      "title": "Connection Events Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(rano_events_total{event=\"connect\"}[5m])",
          "legendFormat": "connects/s"
        },
        {
          "expr": "rate(rano_events_total{event=\"close\"}[5m])",
          "legendFormat": "closes/s"
        }
      ]
    },
    {
      "title": "Alerts",
      "type": "stat",
      "targets": [
        {
          "expr": "increase(rano_alerts_total[1h])",
          "legendFormat": "Alerts (1h)"
        }
      ]
    }
  ]
}
```

#### PromQL запити

```promql
# Connections by provider
rano_connections_total

# Connection rate per minute
rate(rano_events_total{event="connect"}[1m]) * 60

# Alert rate
increase(rano_alerts_total[1h])

# Provider distribution (%)
rano_connections_total / ignoring(provider) group_left sum(rano_connections_total) * 100
```

### Alertmanager Rules

```yaml
# /etc/prometheus/rules/rano.yml
groups:
  - name: rano
    rules:
      - alert: RanoDown
        expr: rano_up == 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "rano database unavailable"

      - alert: RanoHighUnknownConnections
        expr: rano_connections_total{provider="unknown"} > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High number of unknown provider connections"

      - alert: RanoAlertTriggered
        expr: increase(rano_alerts_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "rano alert triggered"
```

---

## Сценарії використання

### 1. Security Audit

**Мета:** Виявити несанкціоновані з'єднання від AI CLI.

```bash
# Запуск з алертами
rano --preset audit \
  --alert-unknown-domain \
  --alert-domain "*.suspicious.com" \
  --sqlite /var/log/rano/audit.sqlite

# Аналіз
rano report --latest --sqlite /var/log/rano/audit.sqlite
sqlite3 /var/log/rano/audit.sqlite "SELECT * FROM events WHERE alert=1;"
```

### 2. Cost Estimation

**Мета:** Оцінити кількість API calls для розрахунку витрат.

```bash
# Моніторинг сесії
rano --pattern claude --sqlite /tmp/session.sqlite

# Підрахунок calls
rano export --format jsonl --sqlite /tmp/session.sqlite | \
  jq 'select(.event == "connect") | .domain' | \
  grep -c "api.anthropic.com"
```

### 3. CI/CD Integration

**Мета:** Перевірка мережевої активності в CI pipeline.

```yaml
# .github/workflows/ai-audit.yml
- name: Run AI task with monitoring
  run: |
    rano --preset ci --once --sqlite /tmp/ci.sqlite &
    RANO_PID=$!

    # Your AI task
    claude "generate code"

    kill $RANO_PID 2>/dev/null || true

- name: Check for unauthorized connections
  run: |
    UNKNOWN=$(rano export --format jsonl --sqlite /tmp/ci.sqlite | \
      jq -r 'select(.provider == "unknown") | .domain' | wc -l)
    if [ "$UNKNOWN" -gt 0 ]; then
      echo "Found $UNKNOWN unauthorized connections"
      exit 1
    fi
```

### 4. Development Debugging

**Мета:** Зрозуміти мережеву поведінку AI інструментів.

```bash
# Verbose mode з ancestry
rano --preset verbose --show-ancestry --pattern claude

# Аналіз по процесах
rano export --format jsonl | \
  jq -r '.ancestry_path' | sort | uniq -c | sort -rn
```

### 5. Compliance Logging

**Мета:** Довгострокове логування для compliance (GDPR, SOC2).

```bash
# Systemd service з ротацією
rano --pattern claude --pattern codex --pattern gemini \
  --sqlite /var/log/rano/compliance-$(date +%Y-%m).sqlite \
  --log-dir /var/log/rano/daily

# Cron для ротації
0 0 1 * * mv /var/log/rano/compliance-*.sqlite /var/log/rano/archive/
```

---

## Troubleshooting

### "no matching processes"

```bash
# Перевірити чи процес запущений
ps aux | grep -i claude
pgrep -a claude

# Вказати PID напряму
rano --pid $(pgrep claude)
```

### "domains are unknown"

```bash
# Перевірити DNS
dig -x 104.18.32.7

# Увімкнути DNS lookups
rano --domain-mode ptr

# Або pcap для точності
sudo rano --domain-mode pcap
```

### "pcap capture requires elevated privileges"

```bash
# Запустити з sudo
sudo rano --pcap

# Або надати capabilities
sudo setcap cap_net_raw+ep $(which rano)
```

### "SQLite file is locked"

```bash
# Використати нову базу
rano --sqlite /tmp/rano-$(date +%s).sqlite

# Або зупинити інший процес
pkill rano
```

---

## Довідка команд

| Команда | Опис |
|---------|------|
| `rano` | Live моніторинг |
| `rano report` | Звіти з SQLite |
| `rano export` | Експорт CSV/JSONL |
| `rano config check` | Валідація конфігу |
| `rano config show` | Показати конфіг |
| `rano config paths` | Шляхи до конфігів |
| `rano status` | One-line статус для prompt |
| `rano update` | Оновлення binary |
| `rano --list-presets` | Список пресетів |
| `rano --help` | Довідка |
| `rano --version` | Версія |

---

## Посилання

### rano
- [GitHub Repository](https://github.com/Dicklesworthstone/rano)

### Netdata
- [Netdata External Plugins](https://learn.netdata.cloud/docs/developer-and-contributor-corner/external-plugins)
- [Netdata charts.d.plugin](https://learn.netdata.cloud/docs/developer-and-contributor-corner/external-plugins/charts.d.plugin)

### Prometheus / Grafana
- [Prometheus Writing Exporters](https://prometheus.io/docs/instrumenting/writing_exporters/)
- [Node Exporter Textfile Collector](https://github.com/prometheus/node_exporter#textfile-collector)
- [script_exporter](https://github.com/ricoberger/script_exporter)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)
