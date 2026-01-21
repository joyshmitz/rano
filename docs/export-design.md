# Export Subcommand Design

Status: design for bead bd-2a6 (parent: bd-1vz)

## Overview

The export subcommand enables users to extract connection events from rano's SQLite database in machine-readable formats for further analysis, archival, or integration with other tools.

## CLI Design

```bash
# Export all events as CSV
rano export --format csv

# Export as JSONL (JSON Lines)
rano export --format jsonl

# Export with time filters
rano export --format csv --since 24h
rano export --format csv --since 2026-01-17 --until 2026-01-18
rano export --format jsonl --since 2026-01-17T10:00:00Z

# Export specific session
rano export --format csv --run-id "12345-1705512345000"

# Filter by provider
rano export --format csv --provider anthropic
rano export --format csv --provider anthropic --provider openai

# Filter by domain pattern (glob)
rano export --format csv --domain "*.anthropic.com"
rano export --format csv --domain "api.*"

# Custom field selection
rano export --format csv --fields ts,provider,remote_ip,domain

# CSV without header
rano export --format csv --no-header

# Specify SQLite file
rano export --format csv --sqlite /path/to/rano.sqlite

# Output to file (default: stdout)
rano export --format csv --output /tmp/events.csv
rano export --format jsonl -o /tmp/events.jsonl
```

### Flag Summary

| Flag | Description | Default |
|------|-------------|---------|
| `--format <csv\|jsonl>` | Output format (required) | - |
| `--sqlite <path>` | SQLite database path | observer.sqlite |
| `--since <ts>` | Start of time range (UTC or relative) | - |
| `--until <ts>` | End of time range (UTC, exclusive) | now |
| `--run-id <id>` | Export specific session | - |
| `--provider <name>` | Filter by provider (repeatable) | all |
| `--domain <pattern>` | Filter by domain glob pattern (repeatable) | all |
| `--fields <list>` | Comma-separated field list | all fields |
| `--no-header` | Omit header row (CSV only) | false |
| `--output <path>` / `-o` | Output file path | stdout |

### Time Filter Formats

Consistent with `rano report`:

| Format | Example | Interpretation |
|--------|---------|----------------|
| RFC3339 | `2026-01-17T12:34:56Z` | Exact timestamp |
| Date | `2026-01-17` | `2026-01-17T00:00:00Z` |
| Relative | `24h`, `7d`, `30m` | Subtract from now |

### Mutual Exclusivity

- `--run-id` and `--since`/`--until` can be combined (filter within session)
- `--no-header` is ignored for JSONL format

## Field Order and Names

### Default Field List (14 fields)

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | `ts` | string | RFC3339 UTC timestamp |
| 2 | `run_id` | string | Session identifier |
| 3 | `event` | string | `connect` or `close` |
| 4 | `provider` | string | `anthropic`, `openai`, `google`, `unknown` |
| 5 | `pid` | integer | Process ID |
| 6 | `comm` | string | Process command name |
| 7 | `cmdline` | string | Full command line |
| 8 | `proto` | string | `tcp` or `udp` |
| 9 | `local_ip` | string | Local IP address |
| 10 | `local_port` | integer | Local port number |
| 11 | `remote_ip` | string | Remote IP address |
| 12 | `remote_port` | integer | Remote port number |
| 13 | `domain` | string | Resolved domain (may be empty) |
| 14 | `duration_ms` | integer | Connection duration (close events only) |

### Field Selection

Users can customize output with `--fields`:

```bash
# Minimal export
rano export --format csv --fields ts,provider,remote_ip,domain

# Network-focused export
rano export --format csv --fields ts,proto,local_ip,local_port,remote_ip,remote_port

# Process-focused export
rano export --format csv --fields ts,pid,comm,cmdline,provider
```

Invalid field names produce an error:
```
Error: Unknown field 'invalid_field'. Valid fields: ts, run_id, event, ...
```

## CSV Format Specification

### RFC 4180 Compliance

The CSV output follows [RFC 4180](https://datatracker.ietf.org/doc/html/rfc4180):

1. **Header row**: First row contains field names (unless `--no-header`)
2. **Field separator**: Comma (`,`)
3. **Record separator**: CRLF (`\r\n`) for Excel compatibility
4. **Quoting**: Fields containing commas, quotes, or newlines are enclosed in double quotes
5. **Quote escaping**: Double quotes within quoted fields are escaped by doubling (`""`)
6. **Encoding**: UTF-8

### Example CSV Output

```csv
ts,run_id,event,provider,pid,comm,cmdline,proto,local_ip,local_port,remote_ip,remote_port,domain,duration_ms
2026-01-17T12:34:56Z,12345-1705512345000,connect,anthropic,1234,claude,/usr/bin/claude,tcp,127.0.0.1,54321,34.149.66.137,443,api.anthropic.com,
2026-01-17T12:35:01Z,12345-1705512345000,close,anthropic,1234,claude,/usr/bin/claude,tcp,127.0.0.1,54321,34.149.66.137,443,api.anthropic.com,5000
```

### Escaping Rules

| Content | Input | Output |
|---------|-------|--------|
| Plain text | `hello` | `hello` |
| Contains comma | `hello, world` | `"hello, world"` |
| Contains quote | `say "hi"` | `"say ""hi"""` |
| Contains newline | `line1\nline2` | `"line1\nline2"` |
| Empty | `` | `` |
| Null | (SQL NULL) | `` |

### Implementation: csv_escape Function

```rust
fn csv_escape(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }

    let needs_quoting = value.contains(',')
        || value.contains('"')
        || value.contains('\n')
        || value.contains('\r');

    if needs_quoting {
        let escaped = value.replace('"', "\"\"");
        format!("\"{}\"", escaped)
    } else {
        value.to_string()
    }
}
```

## JSONL Format Specification

### Format Rules

1. **One object per line**: Each event is a complete JSON object on a single line
2. **Line separator**: LF (`\n`) - Unix-style
3. **Encoding**: UTF-8
4. **Key order**: Alphabetical for deterministic output
5. **Null handling**: Omit keys with null values (keep output compact)

### Example JSONL Output

```jsonl
{"comm":"claude","cmdline":"/usr/bin/claude","domain":"api.anthropic.com","event":"connect","local_ip":"127.0.0.1","local_port":54321,"pid":1234,"proto":"tcp","provider":"anthropic","remote_ip":"34.149.66.137","remote_port":443,"run_id":"12345-1705512345000","ts":"2026-01-17T12:34:56Z"}
{"comm":"claude","cmdline":"/usr/bin/claude","domain":"api.anthropic.com","duration_ms":5000,"event":"close","local_ip":"127.0.0.1","local_port":54321,"pid":1234,"proto":"tcp","provider":"anthropic","remote_ip":"34.149.66.137","remote_port":443,"run_id":"12345-1705512345000","ts":"2026-01-17T12:35:01Z"}
```

### Field Selection with JSONL

When `--fields` is used, only the specified fields appear in each JSON object:

```bash
rano export --format jsonl --fields ts,provider,domain
```

Output:
```jsonl
{"domain":"api.anthropic.com","provider":"anthropic","ts":"2026-01-17T12:34:56Z"}
```

### Implementation: JSON Serialization

No external JSON crate required; build strings manually (consistent with existing codebase):

```rust
fn event_to_jsonl(event: &ExportEvent, fields: &[String]) -> String {
    let mut pairs: Vec<String> = Vec::new();

    for field in fields {
        if let Some(value) = event.get_field(field) {
            pairs.push(format!("\"{}\":{}", field, json_value(&value)));
        }
    }

    format!("{{{}}}", pairs.join(","))
}

fn json_value(value: &FieldValue) -> String {
    match value {
        FieldValue::String(s) => format!("\"{}\"", json_escape(s)),
        FieldValue::Integer(n) => n.to_string(),
        FieldValue::Null => "null".to_string(),
    }
}
```

## Domain Filtering

### Glob Pattern Matching

The `--domain` flag uses case-insensitive glob patterns:

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `*.anthropic.com` | `api.anthropic.com`, `www.anthropic.com` | `anthropic.com` |
| `api.*` | `api.anthropic.com`, `api.openai.com` | `www.anthropic.com` |
| `*google*` | `www.google.com`, `googleapis.com` | `openai.com` |

### Multiple Domain Filters

Multiple `--domain` patterns are OR'd together:

```bash
rano export --format csv --domain "*.anthropic.com" --domain "*.openai.com"
# Exports events matching EITHER pattern
```

### SQL Implementation

```sql
SELECT * FROM events
WHERE (
    domain LIKE '%anthropic.com'  -- converted from *.anthropic.com
    OR domain LIKE 'api.%'        -- converted from api.*
)
```

## Data Structures

### ExportArgs Struct

```rust
#[derive(Clone, Debug)]
struct ExportArgs {
    /// Output format (required)
    format: ExportFormat,

    /// SQLite database path
    sqlite_path: String,

    /// Time filter: start (inclusive)
    since: Option<String>,

    /// Time filter: end (exclusive)
    until: Option<String>,

    /// Session filter
    run_id: Option<String>,

    /// Provider filters (OR'd together)
    providers: Vec<String>,

    /// Domain glob patterns (OR'd together)
    domain_patterns: Vec<String>,

    /// Custom field selection
    fields: Option<Vec<String>>,

    /// Omit header row (CSV only)
    no_header: bool,

    /// Output file (None = stdout)
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum ExportFormat {
    Csv,
    Jsonl,
}

impl Default for ExportArgs {
    fn default() -> Self {
        Self {
            format: ExportFormat::Csv, // Will error if not specified
            sqlite_path: "observer.sqlite".to_string(),
            since: None,
            until: None,
            run_id: None,
            providers: Vec::new(),
            domain_patterns: Vec::new(),
            fields: None,
            no_header: false,
            output: None,
        }
    }
}
```

### ExportFilter Struct

```rust
struct ExportFilter {
    run_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    providers: Vec<String>,
    domain_patterns: Vec<String>,
}
```

### Field Constants

```rust
const ALL_FIELDS: &[&str] = &[
    "ts", "run_id", "event", "provider", "pid", "comm", "cmdline",
    "proto", "local_ip", "local_port", "remote_ip", "remote_port",
    "domain", "duration_ms"
];

fn validate_fields(fields: &[String]) -> Result<(), String> {
    for field in fields {
        if !ALL_FIELDS.contains(&field.as_str()) {
            return Err(format!(
                "Unknown field '{}'. Valid fields: {}",
                field,
                ALL_FIELDS.join(", ")
            ));
        }
    }
    Ok(())
}
```

## Query Building

### Base Query

```sql
SELECT ts, run_id, event, provider, pid, comm, cmdline,
       proto, local_ip, local_port, remote_ip, remote_port,
       domain, duration_ms
FROM events
WHERE 1=1
```

### Filter Application

```rust
fn build_export_query(filter: &ExportFilter, fields: &[String]) -> (String, Vec<String>) {
    let field_list = if fields.is_empty() {
        ALL_FIELDS.join(", ")
    } else {
        fields.join(", ")
    };

    let mut sql = format!("SELECT {} FROM events WHERE 1=1", field_list);
    let mut params: Vec<String> = Vec::new();

    // Time filters
    if let Some(ref run_id) = filter.run_id {
        sql.push_str(" AND run_id = ?");
        params.push(run_id.clone());
    }
    if let Some(ref since) = filter.since {
        sql.push_str(" AND ts >= ?");
        params.push(since.clone());
    }
    if let Some(ref until) = filter.until {
        sql.push_str(" AND ts < ?");
        params.push(until.clone());
    }

    // Provider filter (OR'd)
    if !filter.providers.is_empty() {
        let placeholders: Vec<&str> = filter.providers.iter().map(|_| "?").collect();
        sql.push_str(&format!(" AND provider IN ({})", placeholders.join(",")));
        params.extend(filter.providers.clone());
    }

    // Domain patterns (converted to LIKE, OR'd)
    if !filter.domain_patterns.is_empty() {
        let conditions: Vec<String> = filter.domain_patterns
            .iter()
            .map(|_| "domain LIKE ?")
            .collect();
        sql.push_str(&format!(" AND ({})", conditions.join(" OR ")));
        for pattern in &filter.domain_patterns {
            params.push(glob_to_sql_like(pattern));
        }
    }

    // Deterministic ordering
    sql.push_str(" ORDER BY ts ASC");

    (sql, params)
}

fn glob_to_sql_like(pattern: &str) -> String {
    // Convert glob wildcards to SQL LIKE:
    // * -> %
    // ? -> _
    // Escape existing % and _ characters
    pattern
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('*', "%")
        .replace('?', "_")
}
```

## Output Flow

### Streaming Architecture

Export uses streaming to handle large datasets without loading all events into memory:

```
┌─────────────────┐
│  SQLite Query   │
│  (with filters) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Row Iterator   │
│  (lazy cursor)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Format Row     │
│  (CSV/JSONL)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Write Output   │
│  (stdout/file)  │
└────────┬────────┘
```

### Implementation Sketch

```rust
fn run_export(args: &ExportArgs) -> Result<(), String> {
    // Open database
    let conn = Connection::open(&args.sqlite_path)
        .map_err(|e| format!("Failed to open database: {}", e))?;

    // Validate fields
    let fields = args.fields.clone().unwrap_or_else(|| {
        ALL_FIELDS.iter().map(|s| s.to_string()).collect()
    });
    validate_fields(&fields)?;

    // Build query
    let filter = ExportFilter { /* ... */ };
    let (sql, params) = build_export_query(&filter, &fields);

    // Open output
    let mut output: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(File::create(path)
            .map_err(|e| format!("Failed to create output file: {}", e))?),
        None => Box::new(io::stdout()),
    };

    // Write header (CSV only)
    if args.format == ExportFormat::Csv && !args.no_header {
        writeln!(output, "{}", fields.join(","))
            .map_err(|e| format!("Write error: {}", e))?;
    }

    // Stream rows
    let mut stmt = conn.prepare(&sql)
        .map_err(|e| format!("Query error: {}", e))?;

    let params_refs: Vec<&dyn rusqlite::ToSql> =
        params.iter().map(|s| s as &dyn rusqlite::ToSql).collect();

    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        Ok(row_to_event(row, &fields)?)
    }).map_err(|e| format!("Query error: {}", e))?;

    for row_result in rows {
        let event = row_result.map_err(|e| format!("Row error: {}", e))?;
        let line = match args.format {
            ExportFormat::Csv => event_to_csv(&event, &fields),
            ExportFormat::Jsonl => event_to_jsonl(&event, &fields),
        };
        writeln!(output, "{}", line)
            .map_err(|e| format!("Write error: {}", e))?;
    }

    Ok(())
}
```

## Error Cases

| Condition | Error Message |
|-----------|---------------|
| Missing `--format` | `Error: --format is required (use csv or jsonl)` |
| Invalid format | `Error: Invalid format 'foo'. Use 'csv' or 'jsonl'` |
| SQLite not found | `Error: SQLite file not found: {path}` |
| No events table | `Error: Database does not contain rano data` |
| Invalid field | `Error: Unknown field 'foo'. Valid fields: ts, run_id, ...` |
| Invalid time format | `Error: Invalid timestamp format: {value}` |
| No matching events | (Produces empty output, not an error) |
| Output file error | `Error: Failed to create output file: {details}` |

## Performance Considerations

1. **Streaming**: No limit on export size; memory usage is constant
2. **Indexing**: Queries use existing indexes on `ts`, `run_id`, `provider`, `domain`
3. **Buffered I/O**: Use `BufWriter` for file output to reduce syscalls
4. **Field selection**: Only query selected fields (reduces data transfer)

## Testing Requirements

### Unit Tests

1. `csv_escape` function with various inputs
2. `glob_to_sql_like` conversion
3. Field validation (valid and invalid fields)
4. Query building with various filter combinations
5. JSONL serialization

### Integration Tests

1. Export all events (default)
2. Export with time filters
3. Export with provider filters
4. Export with domain filters
5. Export with field selection
6. Export to file vs stdout
7. CSV with and without header
8. Empty result set (no matching events)

### E2E Tests

1. Round-trip: export CSV, reimport, verify data integrity
2. Excel compatibility: open CSV in spreadsheet software
3. Large dataset: export 100,000+ events without memory issues

---

*This design document addresses the deliverables specified in bd-2a6 and provides the foundation for bd-1gl (Implement export subcommand).*
