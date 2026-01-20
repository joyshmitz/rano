# Report Subcommand Design

Status: design for bead rust_agent_network_observer-35w.2.1

## CLI Design

```bash
# Show latest session report
rano report --latest

# Show specific session by run_id
rano report --run-id "1234-1705512345000"

# Show report for time range (UTC timestamps)
rano report --since "2026-01-17T00:00:00Z" --until "2026-01-18T00:00:00Z"

# Show report for relative time range
rano report --since "1h"    # last hour
rano report --since "24h"   # last 24 hours
rano report --since "7d"    # last 7 days

# Output format
rano report --latest --json

# Limit top-N entries in lists
rano report --latest --top 10

# Specify SQLite file (if not default)
rano report --sqlite /path/to/rano.sqlite --latest
```

### Flag Summary

| Flag | Description | Default |
|------|-------------|---------|
| `--latest` | Report on most recent session | - |
| `--run-id <id>` | Report on specific session | - |
| `--since <ts>` | Start of time range (UTC or relative) | - |
| `--until <ts>` | End of time range (UTC, exclusive) | now |
| `--json` | Output as JSON | false |
| `--top <n>` | Limit top-N entries | 10 |
| `--sqlite <path>` | SQLite database path | observer.sqlite |

### Mutual Exclusivity

- `--latest` and `--run-id` are mutually exclusive
- `--since`/`--until` can combine with neither (aggregate mode) or `--run-id` (filter within session)

## Time Range Semantics

### Timestamp Format

- All timestamps in SQLite are stored as **RFC3339 UTC** (`2026-01-17T12:34:56Z`)
- CLI accepts:
  - RFC3339 format: `2026-01-17T12:34:56Z`
  - ISO-8601 date only: `2026-01-17` (interpreted as `2026-01-17T00:00:00Z`)
  - Relative duration: `1h`, `24h`, `7d`, `30m` (from now, going backwards)

### Range Semantics

- `--since`: **inclusive** (includes events at exact timestamp)
- `--until`: **exclusive** (excludes events at exact timestamp)
- This matches standard interval notation `[since, until)`

### Relative Time Parsing

```
1h   -> 1 hour ago
24h  -> 24 hours ago
7d   -> 7 days ago
30m  -> 30 minutes ago
```

## Report Sections

### Session Info (when --run-id or --latest)

```
Session: 1234-1705512345000
Started: 2026-01-17T12:34:56Z
Ended:   2026-01-17T14:00:00Z
Host:    myhost
User:    ubuntu
Patterns: claude, codex, gemini
Duration: 1h 25m 4s
```

Source: `sessions` table

### Summary Statistics

```
Events:     1,234 connects, 1,180 closes
Active:     54 (peak: 89)
Avg duration: 45.2s
Max duration: 5m 32s
```

Source: `events` table aggregates or `sessions.connects/closes`

### Provider Breakdown

```
Provider    Connects  Closes  Domains  IPs
----------  --------  ------  -------  ---
anthropic      789     750       12     8
openai         345     330        8     4
google         100      95        5     3
unknown          0       5        2     2
```

Source: `provider_counts` view + count distinct from events

### Top Domains (per provider)

```
Top Domains (anthropic):
  1. api.anthropic.com        456 events
  2. console.anthropic.com     89 events
  ...

Top Domains (openai):
  1. api.openai.com           234 events
  ...
```

Source: `provider_domains` view, ordered by events DESC, LIMIT --top

### Top IPs (per provider)

```
Top IPs (anthropic):
  1. 34.149.66.137            567 events
  2. 34.36.57.103             123 events
  ...
```

Source: `provider_ips` view, ordered by events DESC, LIMIT --top

### Hourly Activity (if time range spans multiple hours)

```
Hourly Activity:
  2026-01-17T12:00:00Z  anthropic: 45, openai: 23
  2026-01-17T13:00:00Z  anthropic: 89, openai: 56
  ...
```

Source: `provider_hourly` view, filtered by time range

## Queries by Section

| Section | Query/View | Filters |
|---------|-----------|---------|
| Session Info | `sessions WHERE run_id = ?` | run_id |
| Summary | `SELECT COUNT(*) ... FROM events` | run_id or ts range |
| Provider Breakdown | `provider_counts` or aggregate | run_id or ts range |
| Top Domains | `provider_domains ORDER BY events DESC LIMIT ?` | provider, run_id or ts range |
| Top IPs | `provider_ips ORDER BY events DESC LIMIT ?` | provider, run_id or ts range |
| Hourly Activity | `provider_hourly` | ts range |

For time-filtered queries, views won't work directly; use inline aggregates:

```sql
-- Provider counts for time range
SELECT provider,
       COUNT(*) AS events,
       SUM(CASE WHEN event='connect' THEN 1 ELSE 0 END) AS connects,
       SUM(CASE WHEN event='close' THEN 1 ELSE 0 END) AS closes
FROM events
WHERE ts >= ? AND ts < ?
GROUP BY provider;
```

## Compatibility Behavior

### Missing Tables/Views

1. Check schema on connect:
   ```sql
   SELECT name FROM sqlite_master WHERE type='table' AND name='events';
   SELECT name FROM sqlite_master WHERE type='view' AND name='provider_counts';
   ```

2. If `events` table missing: error with clear message
   ```
   Error: SQLite file does not contain rano event data
   ```

3. If views missing but `events` exists: warn and use inline queries
   ```
   Warning: SQLite views not found, using fallback queries (slower)
   ```

### Schema Version

Future: add `schema_version` to sessions or separate metadata table. For now, assume compatible if `events` table has expected columns.

## JSON Output Format

### Stable Keys (alphabetical)

```json
{
  "hourly_activity": [...],
  "provider_breakdown": [...],
  "session": {...},
  "summary": {...},
  "top_domains": {...},
  "top_ips": {...}
}
```

### Session Object

```json
{
  "session": {
    "args": "rano --pattern claude",
    "duration_seconds": 5104,
    "end_ts": "2026-01-17T14:00:00Z",
    "host": "myhost",
    "patterns": "claude, codex, gemini",
    "run_id": "1234-1705512345000",
    "start_ts": "2026-01-17T12:34:56Z",
    "user": "ubuntu"
  }
}
```

### Summary Object

```json
{
  "summary": {
    "active": 54,
    "avg_duration_ms": 45200,
    "closes": 1180,
    "connects": 1234,
    "max_duration_ms": 332000,
    "peak_active": 89
  }
}
```

### Provider Breakdown Array

```json
{
  "provider_breakdown": [
    {
      "closes": 750,
      "connects": 789,
      "domains": 12,
      "ips": 8,
      "provider": "anthropic"
    }
  ]
}
```

### Top Domains/IPs Object

```json
{
  "top_domains": {
    "anthropic": [
      {"domain": "api.anthropic.com", "events": 456},
      {"domain": "console.anthropic.com", "events": 89}
    ],
    "openai": [...]
  },
  "top_ips": {
    "anthropic": [
      {"events": 567, "ip": "34.149.66.137"},
      {"events": 123, "ip": "34.36.57.103"}
    ]
  }
}
```

### Hourly Activity Array

```json
{
  "hourly_activity": [
    {
      "anthropic": 45,
      "google": 10,
      "hour": "2026-01-17T12:00:00Z",
      "openai": 23,
      "unknown": 0
    }
  ]
}
```

## Deterministic Ordering

- Provider breakdown: alphabetical by provider name
- Top domains/IPs: by event count DESC, then alphabetically
- Hourly activity: chronological (ASC by hour)
- JSON keys: alphabetical at every level

## Error Cases

| Condition | Behavior |
|-----------|----------|
| SQLite file not found | Error: "SQLite file not found: {path}" |
| No events table | Error: "Database does not contain rano data" |
| No matching sessions | Error: "No sessions found matching criteria" |
| Invalid time format | Error: "Invalid timestamp format: {value}" |
| Both --latest and --run-id | Error: "--latest and --run-id are mutually exclusive" |
