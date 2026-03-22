# Changelog

All notable changes to [rano](https://github.com/Dicklesworthstone/rano) are documented here.

rano is a network observer for AI CLI processes (Claude Code, Codex CLI, Gemini CLI).
It polls `/proc`, maps sockets to PIDs, and prints connection events with provider tags
while logging a complete history to SQLite.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

Commits on `main` since v0.1.0 (2026-03-19).

### Changed

- Removed dead `self_update_windows` code left over after dropping Windows builds
  ([961cad8](https://github.com/Dicklesworthstone/rano/commit/961cad89a9fa99e2d2aae0b1587579c2a310aeb8))
- Cleaned up dead Windows install path from docs and CI
  ([7ebc740](https://github.com/Dicklesworthstone/rano/commit/7ebc74072e58d4f866914d2e27a81505a4d5c62b))
- Style cleanup: removed extra blank lines left after Windows code removal
  ([d6175dd](https://github.com/Dicklesworthstone/rano/commit/d6175dd43eac98ac0aca06a99588f92df681614e))

---

## [v0.1.0] -- 2026-03-19 (GitHub Release)

> First official release. Published to GitHub Releases with pre-built binaries for
> Linux (x86_64, aarch64) and macOS (x86_64, aarch64). Windows is intentionally
> excluded -- rano depends on Unix-only `/proc` and libc APIs.
>
> **Install:** `curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/rano/main/install.sh | bash`

Tag [`v0.1.0`](https://github.com/Dicklesworthstone/rano/releases/tag/v0.1.0)
covers the entire development history from the initial commit (2026-01-17) through
release prep on 2026-03-19 (113 commits).

### Core Monitoring Engine (2026-01-17)

The foundational poll-based observer, landed in the initial commit and refined
over the following days.

- **`/proc` polling loop**: reads `/proc/net/tcp` and `/proc/[pid]/fd` to map
  open sockets to PIDs and command lines without ptrace or eBPF
  ([dcecf6c](https://github.com/Dicklesworthstone/rano/commit/dcecf6ce04482c99d57bb1bc38e7935ddf82722c))
- **Provider attribution**: classifies connections as `anthropic`, `openai`,
  `google`, or `unknown` based on reverse DNS and known IP ranges
- **Descendant tracking**: follows child processes automatically via
  `/proc/[pid]/children`; disable with `--no-descendants`
- **Live stats panel**: in-terminal summaries with top IPs/domains, provider
  totals, and ASCII bar charts (`--stats-interval-ms`, `--stats-width`,
  `--stats-top`)
- **Flexible output**: `--json` for JSON lines, `--summary-only` to suppress
  live events, `--log-file` / `--log-dir` for file output
- **`--once` mode**: single poll and exit for scripting

### SQLite Event Logging (2026-01-17 -- 2026-01-19)

- Durable event storage in SQLite (`--sqlite <path>`, default `observer.sqlite`)
- Built-in aggregate views: `provider_counts`, session summaries
- Configurable batching: `--db-batch-size`, `--db-flush-ms`, `--db-queue-max`
  ([2761765](https://github.com/Dicklesworthstone/rano/commit/2761765e6867e2b891dd8c3aac99782e54b6ddc4))
- `--no-sqlite` to disable persistence entirely

### Domain Attribution Modes (2026-01-17 -- 2026-01-25)

- **PTR mode** (default): reverse DNS lookups via `getnameinfo`, no elevated
  privileges required
- **pcap mode** (feature-gated, `cargo build --features pcap`): libpcap-based
  capture of DNS responses and TLS SNI for accurate domain attribution;
  requires root/CAP_NET_RAW
  ([759b7c5](https://github.com/Dicklesworthstone/rano/commit/759b7c5d30ebfc5bc6cd392cc8e2169713d01bd8))
- Automatic pcap-to-PTR fallback when capture is unavailable
- Offline pcap file verification via `RANO_PCAP_FILE` environment variable
- Improved pcap capture reliability
  ([9bedb85](https://github.com/Dicklesworthstone/rano/commit/9bedb859012c6ec107a74f63ae93415160b5f36e))

### Provider Config via TOML (2026-01-17)

- `rano.toml` / `~/.config/rano/rano.toml` for custom provider definitions and
  domain-to-provider mappings
  ([e2d167f](https://github.com/Dicklesworthstone/rano/commit/e2d167f52eb36ed0e0578a66ae66dcfc31a309f9))

### `rano report` Command (2026-01-19)

- Generate session reports from SQLite history: `--latest`, `--run-id`,
  `--since` / `--until` (relative or RFC 3339), `--json`
  ([8278547](https://github.com/Dicklesworthstone/rano/commit/8278547b2401cd28d830b4958b5e72cf53002693))
- Report sections: session metadata, summary, provider breakdown, top domains,
  top IPs

### Alert System (2026-01-21)

- Proactive alerts for suspicious patterns and threshold breaches
  ([b799083](https://github.com/Dicklesworthstone/rano/commit/b799083f1589f023906ebee70d7ae2b6e08d139d))
- Alert flags: `--alert-domain`, `--alert-max-connections`,
  `--alert-max-per-provider`, `--alert-duration-ms`, `--alert-unknown-domain`,
  `--alert-bell`, `--alert-cooldown-ms`
- SQLite alert tracking (`alert=1` column) for post-hoc analysis
  ([8c5bc42](https://github.com/Dicklesworthstone/rano/commit/8c5bc42c3f767c642f68ac2f81273f056c84f9ea))
- Retry/reconnection pattern detection
  ([5e24270](https://github.com/Dicklesworthstone/rano/commit/5e24270f11926bfc59d2ae5d1cf74979e171cdf0))

### Export System (2026-01-21)

- Export events to CSV and JSONL with ancestry information
  ([4d0ae2f](https://github.com/Dicklesworthstone/rano/commit/4d0ae2f158dae693769fdadd421c47dcb0588e23))
- Ancestry cache for efficient process-tree lookups
  ([130122e](https://github.com/Dicklesworthstone/rano/commit/130122e64bac6bba45ee9f2e8f10a470e9f9703f))

### Preset System (2026-01-21)

- Built-in presets: `audit`, `quiet`, `live`, `verbose` via `--preset <name>`
  ([2a49a35](https://github.com/Dicklesworthstone/rano/commit/2a49a35bc22ce8c2860aa123b66590e2010e57eb))
- Custom presets in `~/.config/rano/presets/*.conf`
- `--list-presets` to enumerate available presets
- Multiple presets composable; later wins on conflicts

### `rano diff` Command (2026-02-13)

- Compare two monitoring sessions: `--old <run-id> --new <run-id>`
  ([5834863](https://github.com/Dicklesworthstone/rano/commit/58348636fb9b3c489c156f996f71105a5c3474cd))
- Sections: new/removed/changed domains, new processes, provider count shifts
- `--threshold` to control significance cutoff; `--json` for machine output
- E2E test coverage
  ([ade5805](https://github.com/Dicklesworthstone/rano/commit/ade5805b7a174b993d87fae1435228d40185ff3c))

### `rano status` Command (2026-01-22 -- 2026-02-13)

- One-line status output for shell prompt integration (PS1, starship, etc.)
  ([5e7c445](https://github.com/Dicklesworthstone/rano/commit/5e7c445385ca3a12b10ca44e912d9dac84331b9e))
- Customizable format template: `rano status --format '{active}/{total}'`
- Optimized for prompt use (<50 ms typical)
- E2E test and CI pipeline step
  ([daee398](https://github.com/Dicklesworthstone/rano/commit/daee3980ac0e8e6aaf46c4ded39ec0fbb7e0ac21))

### `rano update` (Self-Updater)

- `rano update` downloads the latest release binary from GitHub Releases
- Supports `--version`, `--system`, `--owner`, `--repo`, `--branch` flags

### Config Validation (2026-01-21 -- 2026-03-19)

- Separate `config_validation.rs` module for validating `rano.toml` files
  ([35f71ea](https://github.com/Dicklesworthstone/rano/commit/35f71eaef91eb1d6ad69107ec4c30403c93440fc))
- Unit tests for provider config overrides and edge cases
  ([539deff](https://github.com/Dicklesworthstone/rano/commit/539deff45704ed958a4d6e944b477a5138eacd8a))
- Clippy-clean match guards
  ([cad677a](https://github.com/Dicklesworthstone/rano/commit/cad677af6e434e500aa62515a6f5e97ea493459f))

### Themes and Accessibility

- `--theme <vivid|mono|colorblind>` for color accessibility
- `--color <auto|always|never>` / `--no-color` for ANSI control
- `--no-banner` to suppress startup banner

### Cross-Platform Fixes

- BSD/macOS support for `reverse_dns` socket structures (4.4BSD `sin_len`
  differences)
  ([876f5f4](https://github.com/Dicklesworthstone/rano/commit/876f5f45d03f7afaea19c90300fcfaffe81b7f6a))
- Reverse DNS byte order fix: `from_ne_bytes` instead of `from_be_bytes`
  ([6bede31](https://github.com/Dicklesworthstone/rano/commit/6bede31ca157b714ccd93a211ac163d773382f32))
- ARM64 compatibility: use `libc::c_char` instead of hardcoded `i8`
  ([10ab758](https://github.com/Dicklesworthstone/rano/commit/10ab758bc598d06593429b8539fad8f64641441f))
- Replace bare division with `checked_div` to prevent potential panic
  ([18d3762](https://github.com/Dicklesworthstone/rano/commit/18d3762d4eaad210e8751039cafcca9431a773e0))

### CI / Release Infrastructure

- CI workflow (`ci.yml`): build + test matrix, clippy, rustfmt, E2E tests
- Distribution workflow (`dist.yml`): cross-compile for four targets
  (x86_64-linux, aarch64-linux, x86_64-darwin, aarch64-darwin)
- Release automation (`release-automation.yml`): tag-triggered binary publishing
- pcap feature CI matrix
  ([bf77dbc](https://github.com/Dicklesworthstone/rano/commit/bf77dbcd38526e1355d7aa1e35914d1cb37e7bef))
- Workflow lint job with actionlint
  ([3c699f9](https://github.com/Dicklesworthstone/rano/commit/3c699f909f50032f0c6c75b5b6d0a9f4951f3acd))
- ACFS notification workflows for installer changes
  ([1c2bf9f](https://github.com/Dicklesworthstone/rano/commit/1c2bf9fe42d9e09aa5e7853900f847334b8cca16))
- Windows target dropped from `dist.yml` (rano uses Unix-only libc APIs)
  ([2875f46](https://github.com/Dicklesworthstone/rano/commit/2875f46d17eadea5da2211150d3169a237564721))
- Switched from stable to nightly Rust toolchain (edition 2024)
  ([a2c0056](https://github.com/Dicklesworthstone/rano/commit/a2c00564a7d212a17be06a1bf052d38fc7c9c28f))

### Installer

- `install.sh`: curl-pipe-bash installer with `--version`, `--system`,
  `--easy-mode` options; architecture auto-detection; SHA256 verification
- `install.ps1`: PowerShell stub that directs Windows users to WSL 2

### Other

- MIT License with OpenAI/Anthropic Rider
  ([b725a13](https://github.com/Dicklesworthstone/rano/commit/b725a136077ebd3bb129338b4b1283bd3620d252))
- Replaced `lumera-ai` references with `Dicklesworthstone`
  ([f1941a0](https://github.com/Dicklesworthstone/rano/commit/f1941a09f5ee6c4068b96ff965a1d2017a984078))
- Dependency upgrades: toml 0.9 -> 1.0, libc, tempfile, rusqlite, and more
- GitHub social preview image
  ([64fcdf9](https://github.com/Dicklesworthstone/rano/commit/64fcdf9a6accdf273e4245fd4345361293f52bca))

---

<!-- link definitions -->
[Unreleased]: https://github.com/Dicklesworthstone/rano/compare/v0.1.0...HEAD
[v0.1.0]: https://github.com/Dicklesworthstone/rano/releases/tag/v0.1.0
