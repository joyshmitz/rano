# Plan: macOS live monitoring via libproc (detailed)

## Goal
Implement live monitoring on macOS using libproc APIs (no /proc), while preserving Linux behavior and output.

## Non-goals
- No changes to the output schema, SQLite schema, or alerting semantics.
- No behavior changes to Linux beyond a refactor into a platform layer.
- Connection lifecycle tracking (separate future plan).

## Compatibility constraints
- Keep Linux output and filtering behavior identical for the same flags.
- Keep provider attribution (comm/cmdline) behavior identical.
- Preserve current state labels (e.g., LISTEN/ESTABLISHED) in output.

## Scope
- Add a platform abstraction layer for process + socket enumeration.
- Implement macOS backend using libproc and XNU proc_info structures.
- Keep Linux backend unchanged in behavior.
- Update docs and validation notes.

---

## Dependency decision (macOS): Hybrid approach

**Use `darwin-libproc = "0.2.0"` for:**
- `proc_listallpids` — well-tested, handles buffer sizing
- `proc_name` — safe string handling
- `proc_pidpath` — safe string handling

**Use direct FFI for:**
- `proc_pidinfo(PROC_PIDLISTFDS)` — darwin-libproc doesn't expose this
- `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` — requires custom structs
- All socket_info structures — must match XNU headers exactly

**Cargo.toml:**
```toml
[target.'cfg(target_os = "macos")'.dependencies]
darwin-libproc = "0.2.0"
```

---

## Phase 0: Pre-flight inventory (read-only)

1) Locate all /proc-dependent functions in `src/main.rs`:
   - `list_pids`, `read_comm`, `read_cmdline`, `read_ppid`
   - `map_inodes`, `read_net_file`, `gather_net_entries`
2) Locate where `map_inodes + gather_net_entries` are used in the polling loop.
3) Confirm where provider attribution uses comm/cmdline (`build_pid_meta_map`).
4) Record a function-to-platform mapping table (Linux -> macOS).
5) Note any Linux-only parsing assumptions (TCP state strings, hex addresses, inode usage).

### Mapping table
| Function | Linux | macOS |
|----------|-------|-------|
| list_pids | `/proc` scan | `proc_listallpids` via darwin-libproc |
| read_comm | `/proc/{pid}/comm` | `proc_name` via darwin-libproc |
| read_cmdline | `/proc/{pid}/cmdline` | `sysctl(KERN_PROCARGS2)` + `proc_pidpath` fallback |
| read_ppid | `/proc/{pid}/stat` | `proc_pidinfo(PROC_PIDTBSDINFO)` direct FFI |
| collect_sockets | `/proc/net/*` + inode mapping | per-pid `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` |

Acceptance:
- Mapping table verified against actual code.

---

## Phase 1: Platform abstraction types

Create `src/platform/mod.rs` with shared types. No behavior changes yet.

### 1.1 TcpState Enum

```rust
/// TCP connection state (platform-independent)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Unconnected,  // UDP pseudo-state
    Unknown,
}

impl TcpState {
    /// Parse from Linux /proc/net/tcp hex state
    pub fn from_linux_hex(hex: &str) -> Self {
        match hex {
            "01" => Self::Established,
            "02" => Self::SynSent,
            "03" => Self::SynReceived,
            "04" => Self::FinWait1,
            "05" => Self::FinWait2,
            "06" => Self::TimeWait,
            "07" => Self::Closed,
            "08" => Self::CloseWait,
            "09" => Self::LastAck,
            "0A" => Self::Listen,
            "0B" => Self::Closing,
            _ => Self::Unknown,
        }
    }

    /// Parse from macOS XNU tcpsi_state
    pub fn from_macos_xnu(state: i32) -> Self {
        match state {
            0 => Self::Closed,
            1 => Self::Listen,
            2 => Self::SynSent,
            3 => Self::SynReceived,
            4 => Self::Established,
            5 => Self::CloseWait,
            6 => Self::FinWait1,
            7 => Self::Closing,
            8 => Self::LastAck,
            9 => Self::FinWait2,
            10 => Self::TimeWait,
            _ => Self::Unknown,
        }
    }

    /// Display as canonical label
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::Closed => "CLOSED",
            Self::Listen => "LISTEN",
            Self::SynSent => "SYN-SENT",
            Self::SynReceived => "SYN-RECV",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN-WAIT-1",
            Self::FinWait2 => "FIN-WAIT-2",
            Self::CloseWait => "CLOSE-WAIT",
            Self::Closing => "CLOSING",
            Self::LastAck => "LAST-ACK",
            Self::TimeWait => "TIME-WAIT",
            Self::Unconnected => "UNCONN",
            Self::Unknown => "UNKNOWN",
        }
    }
}
```

### 1.2 SocketCollectOpts

```rust
/// Options for socket collection
pub struct SocketCollectOpts {
    pub include_udp: bool,
    pub include_listening: bool,
    pub target_ports: Option<HashSet<u16>>,
}

impl Default for SocketCollectOpts {
    fn default() -> Self {
        Self {
            include_udp: false,
            include_listening: false,  // CLI: --include-listening enables this
            target_ports: None,
        }
    }
}
```

### 1.3 SocketObs

```rust
/// Observed socket connection
pub struct SocketObs {
    pub pid: u32,
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: TcpState,
}
```

### 1.4 CollectStats (error reporting)

```rust
/// Statistics from socket collection
#[derive(Debug, Default)]
pub struct CollectStats {
    pub pids_queried: u32,
    pub pids_accessible: u32,
    pub pids_permission_denied: u32,
    pub pids_not_found: u32,
    pub sockets_found: u32,
}

impl CollectStats {
    pub fn is_degraded(&self) -> bool {
        self.pids_permission_denied > 0
    }

    pub fn warn_if_degraded(&self) {
        if self.pids_permission_denied > 0 && self.pids_accessible == 0 {
            eprintln!("Warning: No process access. Run with sudo for full visibility.");
        } else if self.pids_permission_denied > 0 {
            eprintln!(
                "Warning: {}/{} processes inaccessible. Run with sudo for full visibility.",
                self.pids_permission_denied,
                self.pids_queried
            );
        }
    }
}
```

### 1.5 Public API signature

```rust
// src/platform/mod.rs

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub fn list_pids() -> Vec<u32>;
pub fn read_comm(pid: u32) -> Option<String>;
pub fn read_cmdline(pid: u32) -> Option<String>;
pub fn read_ppid(pid: u32) -> Option<u32>;
pub fn collect_sockets(
    pids: &HashSet<u32>,
    opts: &SocketCollectOpts,
) -> (Vec<SocketObs>, CollectStats);
```

Acceptance:
- Types compile on both platforms.
- No runtime behavior changes.

---

## Phase 2a: macOS FFI definitions

Create `src/platform/macos.rs` with FFI bindings. Linux unchanged.

### Constants (from /usr/include/sys/proc_info.h)

```rust
use libc::{c_int, c_void, c_char};

// proc_pidinfo flavors
const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDTBSDINFO: c_int = 3;

// proc_pidfdinfo flavors
const PROC_PIDFDSOCKETINFO: c_int = 3;

// File descriptor types
const PROX_FDTYPE_SOCKET: u32 = 2;

// Socket info kinds (soi_kind)
const SOCKINFO_IN: c_int = 1;   // UDP
const SOCKINFO_TCP: c_int = 2;  // TCP

// Address families
const AF_INET: c_int = 2;
const AF_INET6: c_int = 30;

// TCP timers array size
const TSI_T_NTIMERS: usize = 4;
```

### Structures

```rust
#[repr(C)]
struct proc_fdinfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
struct proc_fileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

const MAXCOMLEN: usize = 16;

#[repr(C)]
struct proc_bsdinfo {
    pbi_flags: u32,
    pbi_status: u32,
    pbi_xstatus: u32,
    pbi_pid: u32,
    pbi_ppid: u32,
    pbi_uid: u32,
    pbi_gid: u32,
    pbi_ruid: u32,
    pbi_rgid: u32,
    pbi_svuid: u32,
    pbi_svgid: u32,
    rfu_1: u32,
    pbi_comm: [c_char; MAXCOMLEN],
    pbi_name: [c_char; MAXCOMLEN * 2],
    pbi_nfiles: u32,
    pbi_pgid: u32,
    pbi_pjobc: u32,
    e_tdev: u32,
    e_tpgid: u32,
    pbi_nice: i32,
    pbi_start_tvsec: u64,
    pbi_start_tvusec: u64,
}

#[repr(C)]
struct vinfo_stat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
struct sockbuf_info {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct in_addr {
    s_addr: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
union in4in6_addr {
    ia46_addr4: in_addr,
    ia46_pad32: [u32; 4],
}

#[repr(C)]
#[derive(Copy, Clone)]
union in_addr_4_6 {
    ina_46: in4in6_addr,
    ina_6: [u8; 16],
}

#[repr(C)]
struct in_sockinfo_v4 {
    in4_tos: u8,
}

#[repr(C)]
struct in_sockinfo_v6 {
    in6_hlim: u8,
    in6_cksum: c_int,
    in6_ifindex: u16,
    in6_hops: i16,
}

#[repr(C)]
struct in_sockinfo {
    insi_fport: c_int,
    insi_lport: c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: in_addr_4_6,
    insi_laddr: in_addr_4_6,
    insi_v4: in_sockinfo_v4,
    insi_v6: in_sockinfo_v6,
}

#[repr(C)]
struct tcp_sockinfo {
    tcpsi_ini: in_sockinfo,
    tcpsi_state: c_int,
    tcpsi_timer: [c_int; TSI_T_NTIMERS],
    tcpsi_mss: c_int,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
union socket_info_proto {
    pri_in: in_sockinfo,
    pri_tcp: tcp_sockinfo,
}

#[repr(C)]
struct socket_info {
    soi_stat: vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: c_int,
    soi_protocol: c_int,
    soi_family: c_int,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: sockbuf_info,
    soi_snd: sockbuf_info,
    soi_kind: c_int,
    rfu_1: u32,
    soi_proto: socket_info_proto,
}

#[repr(C)]
struct socket_fdinfo {
    pfi: proc_fileinfo,
    psi: socket_info,
}
```

### FFI declarations

```rust
extern "C" {
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;

    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}
```

### Helper: ntohs

```rust
/// Convert port from network byte order to host byte order
#[inline]
fn ntohs(port: c_int) -> u16 {
    u16::from_be(port as u16)
}
```

Acceptance:
- macOS file compiles with `cfg(target_os = "macos")`.
- All structures match XNU headers exactly.

---

## Phase 2b: macOS implementation

Implement macOS functions. Linux still unchanged.

### list_pids()

```rust
pub fn list_pids() -> Vec<u32> {
    darwin_libproc::proc_listallpids()
        .unwrap_or_default()
        .into_iter()
        .filter(|&pid| pid > 0)
        .map(|pid| pid as u32)
        .collect()
}
```

### read_comm()

```rust
pub fn read_comm(pid: u32) -> Option<String> {
    darwin_libproc::proc_name(pid as i32).ok()
}
```

### read_ppid()

```rust
pub fn read_ppid(pid: u32) -> Option<u32> {
    let mut info: proc_bsdinfo = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<proc_bsdinfo>() as c_int,
        )
    };
    if ret > 0 {
        Some(info.pbi_ppid)
    } else {
        None
    }
}
```

### read_cmdline()

```rust
pub fn read_cmdline(pid: u32) -> Option<String> {
    // Try KERN_PROCARGS2 first
    if let Some(cmdline) = read_cmdline_sysctl(pid) {
        return Some(cmdline);
    }
    // Fallback to proc_pidpath
    darwin_libproc::proc_pidpath(pid as i32).ok()
}

fn read_cmdline_sysctl(pid: u32) -> Option<String> {
    use libc::{sysctl, CTL_KERN, KERN_PROCARGS2};
    // Implementation details...
}
```

### collect_sockets()

```rust
pub fn collect_sockets(
    pids: &HashSet<u32>,
    opts: &SocketCollectOpts,
) -> (Vec<SocketObs>, CollectStats) {
    let mut results = Vec::new();
    let mut stats = CollectStats {
        pids_queried: pids.len() as u32,
        ..Default::default()
    };

    for &pid in pids {
        match collect_sockets_for_pid(pid, opts) {
            Ok(sockets) => {
                stats.pids_accessible += 1;
                stats.sockets_found += sockets.len() as u32;
                results.extend(sockets);
            }
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                stats.pids_permission_denied += 1;
            }
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {
                stats.pids_not_found += 1;
            }
            Err(_) => {
                // Other errors: skip silently
            }
        }
    }

    (results, stats)
}

fn collect_sockets_for_pid(
    pid: u32,
    opts: &SocketCollectOpts,
) -> std::io::Result<Vec<SocketObs>> {
    let mut results = Vec::new();

    // Get FD list
    let fds = fetch_fd_list(pid)?;

    for fd_info in fds.iter().filter(|f| f.proc_fdtype == PROX_FDTYPE_SOCKET) {
        // Get socket info
        let mut sock_info: socket_fdinfo = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            proc_pidfdinfo(
                pid as c_int,
                fd_info.proc_fd,
                PROC_PIDFDSOCKETINFO,
                &mut sock_info as *mut _ as *mut c_void,
                std::mem::size_of::<socket_fdinfo>() as c_int,
            )
        };

        if ret <= 0 {
            continue;
        }

        // Filter by address family (IPv4 and IPv6 only)
        let family = sock_info.psi.soi_family;
        if family != AF_INET && family != AF_INET6 {
            continue;
        }

        // Parse based on socket kind
        let (proto, local, remote, state) = match sock_info.psi.soi_kind {
            SOCKINFO_TCP => {
                let tcp = unsafe { sock_info.psi.soi_proto.pri_tcp };
                parse_tcp_socket(&tcp, family)
            }
            SOCKINFO_IN => {
                if !opts.include_udp {
                    continue;
                }
                let udp = unsafe { sock_info.psi.soi_proto.pri_in };
                parse_udp_socket(&udp, family)
            }
            _ => continue,
        };

        // Apply port filter
        if let Some(ref ports) = opts.target_ports {
            if !ports.contains(&local.port()) && !ports.contains(&remote.port()) {
                continue;
            }
        }

        // Apply listening filter
        if state == TcpState::Listen && !opts.include_listening {
            continue;
        }

        results.push(SocketObs {
            pid,
            proto,
            local,
            remote,
            state,
        });
    }

    Ok(results)
}

fn fetch_fd_list(pid: u32) -> std::io::Result<Vec<proc_fdinfo>> {
    // First call to get buffer size
    let size = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };

    if size <= 0 {
        return Err(std::io::Error::last_os_error());
    }

    let count = size as usize / std::mem::size_of::<proc_fdinfo>();
    let mut fds = vec![
        proc_fdinfo { proc_fd: 0, proc_fdtype: 0 };
        count
    ];

    let ret = unsafe {
        proc_pidinfo(
            pid as c_int,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut c_void,
            size,
        )
    };

    if ret <= 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(fds)
}

fn parse_tcp_socket(
    tcp: &tcp_sockinfo,
    family: c_int,
) -> (Proto, SocketAddr, SocketAddr, TcpState) {
    let ini = &tcp.tcpsi_ini;
    let local = parse_sockaddr(ini, family, true);
    let remote = parse_sockaddr(ini, family, false);
    let state = TcpState::from_macos_xnu(tcp.tcpsi_state);
    (Proto::Tcp, local, remote, state)
}

fn parse_udp_socket(
    ini: &in_sockinfo,
    family: c_int,
) -> (Proto, SocketAddr, SocketAddr, TcpState) {
    let local = parse_sockaddr(ini, family, true);
    let remote = parse_sockaddr(ini, family, false);
    (Proto::Udp, local, remote, TcpState::Unconnected)
}

fn parse_sockaddr(ini: &in_sockinfo, family: c_int, local: bool) -> SocketAddr {
    let port = if local {
        ntohs(ini.insi_lport)
    } else {
        ntohs(ini.insi_fport)
    };

    let addr = if local { &ini.insi_laddr } else { &ini.insi_faddr };

    match family {
        AF_INET => {
            let ip = unsafe { addr.ina_46.ia46_addr4.s_addr };
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(u32::from_be(ip))), port)
        }
        AF_INET6 => {
            let ip = unsafe { addr.ina_6 };
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
        _ => unreachable!(),
    }
}
```

Acceptance:
- macOS `--once --pattern <proc>` produces sockets.
- `CollectStats` reports permission issues.

---

## Phase 2c: Linux backend refactor

Move Linux /proc code to `src/platform/linux.rs`. Adapt to new API.

1) Move functions:
   - `list_pids`, `read_comm`, `read_cmdline`, `read_ppid`
   - `read_net_file`, `gather_net_entries`, `parse_addr_port`
   - `map_inodes`, `parse_socket_inode`

2) Implement `collect_sockets` (Linux):
```rust
pub fn collect_sockets(
    pids: &HashSet<u32>,
    opts: &SocketCollectOpts,
) -> (Vec<SocketObs>, CollectStats) {
    let mut stats = CollectStats {
        pids_queried: pids.len() as u32,
        pids_accessible: pids.len() as u32,  // Linux: always accessible
        ..Default::default()
    };

    // Build inode -> pid mapping
    let inode_map = map_inodes(pids);

    // Gather network entries
    let entries = gather_net_entries(opts.include_udp);

    let mut results = Vec::new();
    for (proto, entry) in entries {
        // Map inode to pid
        let pid = match inode_map.get(&entry.inode) {
            Some(&pid) => pid,
            None => continue,
        };

        // Parse state
        let state = TcpState::from_linux_hex(&entry.state);

        // Apply listening filter
        if state == TcpState::Listen && !opts.include_listening {
            continue;
        }

        // Apply port filter
        if let Some(ref ports) = opts.target_ports {
            if !ports.contains(&entry.local_port) && !ports.contains(&entry.remote_port) {
                continue;
            }
        }

        results.push(SocketObs {
            pid,
            proto,
            local: SocketAddr::new(entry.local_ip, entry.local_port),
            remote: SocketAddr::new(entry.remote_ip, entry.remote_port),
            state,
        });

        stats.sockets_found += 1;
    }

    (results, stats)
}
```

Acceptance:
- Linux output matches pre-refactor exactly.
- All existing tests pass.

---

## Phase 2d: Integration testing

Run tests on both platforms before proceeding.

### Linux verification
```bash
# Existing test suite
cargo test

# Manual comparison
./target/release/rano --once --pattern cargo > before.txt
# (after refactor)
./target/release/rano --once --pattern cargo > after.txt
diff before.txt after.txt  # Should be empty
```

### macOS verification
```bash
cargo test

# Compare with lsof
./target/release/rano --once --pattern $$ | head
lsof -i -n -P | grep $$
```

Acceptance:
- Linux: zero regressions.
- macOS: output matches lsof.

---

## Phase 3: Main loop integration

1) Update `main.rs` imports:
```rust
mod platform;
use platform::{collect_sockets, SocketCollectOpts, CollectStats};
```

2) Replace `gather_net_entries + map_inodes` with:
```rust
let opts = SocketCollectOpts {
    include_udp: args.include_udp,
    include_listening: args.include_listening,
    target_ports: None,
};

let (sockets, stats) = platform::collect_sockets(&target_pids, &opts);

// Warn once if degraded
static WARNED: AtomicBool = AtomicBool::new(false);
if stats.is_degraded() && !WARNED.swap(true, Ordering::Relaxed) {
    stats.warn_if_degraded();
}
```

3) Use `SocketObs.state.as_label()` for display.

Acceptance:
- No Linux regressions.
- macOS produces live events.
- Permission warnings appear once.

---

## Phase 4: Documentation updates

1) `README.md`:
   - Update platform support table
   - Remove "Linux-only live monitoring" language
   - Add macOS permissions note

2) `docs/USER_GUIDE.md`:
   - Update platform capabilities table
   - Add macOS section with sudo guidance

Acceptance:
- Docs accurate for both platforms.

---

## Phase 5: CI/CD for macOS

Add macOS to CI pipeline.

### .github/workflows/ci.yml
```yaml
jobs:
  test-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
      - run: cargo build --release

  test-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
      - run: cargo build --release
      - name: Smoke test
        run: |
          ./target/release/rano --once --pattern $$ || true
```

Acceptance:
- CI passes on both Linux and macOS.

---

## Phase 6: Validation

### Automated tests

#### tests/platform_parity.rs
```rust
#[test]
fn test_self_socket_visibility() {
    use std::net::TcpListener;
    use std::collections::HashSet;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let pid = std::process::id();

    let mut pids = HashSet::new();
    pids.insert(pid);
    let opts = SocketCollectOpts {
        include_listening: true,
        ..Default::default()
    };

    let (sockets, stats) = platform::collect_sockets(&pids, &opts);

    assert!(stats.pids_accessible > 0, "Should access own process");
    assert!(
        sockets.iter().any(|s| s.local.port() == port && s.state == TcpState::Listen),
        "Own listening socket should be visible"
    );
}

#[test]
fn test_tcp_state_labels() {
    assert_eq!(TcpState::Listen.as_label(), "LISTEN");
    assert_eq!(TcpState::Established.as_label(), "ESTABLISHED");
    assert_eq!(TcpState::TimeWait.as_label(), "TIME-WAIT");
}

#[test]
fn test_tcp_state_from_linux() {
    assert_eq!(TcpState::from_linux_hex("01"), TcpState::Established);
    assert_eq!(TcpState::from_linux_hex("0A"), TcpState::Listen);
}

#[test]
#[cfg(target_os = "macos")]
fn test_tcp_state_from_macos() {
    assert_eq!(TcpState::from_macos_xnu(4), TcpState::Established);
    assert_eq!(TcpState::from_macos_xnu(1), TcpState::Listen);
}
```

### scripts/validate_macos.sh
```bash
#!/bin/bash
set -e
PROC=${1:-$$}
echo "Comparing rano vs lsof for PID: $PROC"

RANO_OUT=$(./target/release/rano --once --pattern "$PROC" 2>/dev/null | grep -c TCP || echo 0)
LSOF_OUT=$(lsof -i -n -P 2>/dev/null | grep -c "$PROC" || echo 0)

echo "rano TCP connections: $RANO_OUT"
echo "lsof connections: $LSOF_OUT"

if [ "$RANO_OUT" -gt 0 ]; then
    echo "PASS: rano found connections"
else
    echo "WARN: rano found no connections (may need sudo)"
fi
```

### Manual checklist
- macOS:
  - [ ] `rano --once --pattern <proc>` shows sockets
  - [ ] `--include-udp` shows UDP
  - [ ] `--include-listening` shows LISTEN
  - [ ] Test as regular user (partial visibility)
  - [ ] Test with `sudo` (full visibility)
  - [ ] Permission warning appears once, not per-PID
- Linux:
  - [ ] `rano --once` output unchanged
  - [ ] All existing tests pass

---

## Notes

- This plan does NOT include connection lifecycle tracking (separate future work).
- macOS complexity: O(processes × FDs) — acceptable for typical use cases.
- `CollectStats` provides visibility into permission issues.
- No caching or premature optimizations — keep it simple.
