# agentsh on Cloudflare Containers

Secure AI agent code execution on Cloudflare's edge network using [agentsh](https://github.com/canyonroad/agentsh) inside [Cloudflare Containers](https://developers.cloudflare.com/containers/) (Firecracker VMs).

**Live Demo**: https://agentsh-cloudflare.eran-cf2.workers.dev

## What This Demonstrates

agentsh provides defense-in-depth security for AI agent sandboxes: policy-based command blocking, network interception (eBPF/seccomp), filesystem protection (seccomp file monitor + Landlock LSM), and DLP redaction. This project runs agentsh inside Cloudflare Containers to show what works today and what's blocked by the Firecracker VM environment.

## Security Feature Matrix

### Firecracker VM (Cloudflare Containers) vs Docker (local `wrangler dev`)

| Security Feature | Firecracker (Production) | Docker (Local Dev) | Root Cause |
|-----------------|-------------------------|-------------------|------------|
| **Policy enforcement** | Working | Working | Application-level, no kernel dependency |
| **Network: metadata blocking** | Working | Working | eBPF/proxy interception |
| **Network: private IP blocking** | Working | Working | eBPF/proxy interception |
| **Network: external HTTPS** | Working (allowed) | Working (allowed) | Policy allow-list |
| **Seccomp** | Working | Working | `seccomp_user_notify` available |
| **Seccomp file monitor** | **Working** | **Working** | Intercepts file syscalls via `seccomp_unotify` |
| **Landlock LSM** | **Not available** | Working (ABI v5) | Firecracker kernel has ABI v0 (no Landlock) |
| **FUSE filesystem** | **Not available** | **Not available** | Seccomp blocks `mount()` in Firecracker; no `/dev/fuse` in Docker |
| **Filesystem write protection** | **Enforced via seccomp** | **Enforced via Landlock + seccomp** | Seccomp file monitor enforces file_rules policy |
| **DLP redaction** | Proxy traffic only | Proxy traffic only | By design - DLP intercepts API proxy, not stdout |
| **Audit logging** | Disabled (perf) | Working | SQLite fsync is slow in Firecracker |

### What's Needed from Cloudflare

Filesystem protection now works in Firecracker via **seccomp file monitoring** (`seccomp_unotify`). To enable additional defense-in-depth layers:

1. **Landlock LSM support (preferred for defense-in-depth)** - Upgrade Firecracker guest kernel to Linux 5.13+ with Landlock enabled. The current kernel reports Landlock ABI v0 (= not supported). ABI v1+ would add kernel-enforced path-based filesystem access control as a second layer alongside seccomp file monitoring.

2. **FUSE support (for soft-delete/quarantine)** - Allow `mount()` syscall in the Firecracker seccomp profile (or provide `/dev/fuse` with appropriate permissions). FUSE enables workspace overlay features like soft-delete (quarantine deleted files) and file content hashing that seccomp cannot provide.

### Capabilities Detected in Firecracker

```
agentsh 0.9.9
Platform: linux
Security Mode: full
Protection Score: 100%

CAPABILITIES
  capabilities_drop        ✓
  cgroups_v2               ✓
  ebpf                     ✓
  fuse                     ✓  (binary detected, but mount() blocked by seccomp)
  landlock                 -  (kernel does not support Landlock)
  landlock_abi             ✓  (v0 = not supported; needs v1+)
  landlock_network         -
  pid_namespace            -
  seccomp                  ✓
  seccomp_basic            ✓
  seccomp_user_notify      ✓
```

### Capabilities Detected in Local Docker (host kernel 6.18)

```
agentsh 0.9.9
Security Mode: landlock-only
Protection Score: 80%

CAPABILITIES
  capabilities_drop        ✓
  cgroups_v2               ✓
  ebpf                     ✓
  fuse                     -  (no /dev/fuse in Docker)
  landlock                 ✓
  landlock_abi             ✓  (v5)
  landlock_network         ✓
  pid_namespace            -
  seccomp                  ✓
  seccomp_basic            ✓
  seccomp_user_notify      ✓
```

## Detailed Findings

### FUSE: Blocked by Firecracker seccomp

The Firecracker VM has `CAP_SYS_ADMIN` and `fusermount3` is installed, so `agentsh detect` reports `fuse ✓`. However, the Firecracker seccomp profile blocks the `mount()` syscall. When agentsh tries to set up a FUSE overlay filesystem:

- **Non-deferred mode** (`fuse.enabled: true`): The server hangs during session creation when attempting `mount()`. The Firecracker seccomp silently blocks the syscall, causing the FUSE mount to wait indefinitely. The agentsh server becomes unresponsive, and all subsequent `agentsh exec` commands timeout.

- **Deferred mode** (`fuse.enabled: true, deferred: true`): agentsh supports lazy FUSE mounting (mount on first exec, not session creation). However, the server initialization still sets up the FUSE subsystem (platform detection, filesystem interceptor init), which also hangs. This appears to be a bug in agentsh v0.9.9 - deferred mode should fully skip FUSE init at startup.

- **Workaround**: `fuse.enabled: false`. This is the only reliable configuration for Firecracker.

**History**: This has been toggled multiple times in this repo's git history:
```
16c5919 fix: disable FUSE - Firecracker has CAP_SYS_ADMIN but seccomp blocks mount
a1ba2e9 Upgrade agentsh to v0.9.2 and re-enable FUSE
79e497f fix: disable FUSE - Firecracker has CAP_SYS_ADMIN but seccomp blocks mount
eac84ed Upgrade agentsh to v0.9.1 and re-enable FUSE
```

### Landlock: Kernel too old

Landlock LSM (Linux Security Module) provides kernel-enforced path-based filesystem access control. It's the ideal solution for restricting file access in containers because:
- Works even for root processes
- No special devices or mount permissions needed
- Minimal performance overhead
- Default-deny model with explicit allow-lists

The Firecracker guest kernel reports Landlock ABI v0, which means Landlock is **not supported**. Landlock was introduced in Linux 5.13 (ABI v1). The current ABI versions are:
- v1: Basic filesystem access control (Linux 5.13)
- v2: File refer/reparent (Linux 5.19)
- v3: File truncation (Linux 6.2)
- v4: Network TCP bind/connect (Linux 6.7)
- v5: ioctl restrictions (Linux 6.10)

When running locally with `wrangler dev` (Docker), agentsh uses the host kernel which has Landlock ABI v5. This provides full filesystem protection:
```
$ echo "hacked" >> /etc/passwd
/bin/bash: line 1: /etc/passwd: Permission denied

$ touch /usr/bin/malware
touch: cannot touch '/usr/bin/malware': Permission denied
```

The Landlock configuration is kept in `config/agentsh.yaml` and will automatically activate when the Firecracker kernel supports it:

```yaml
landlock:
  enabled: true
  allow_write:
    - "/tmp"
    - "/var/tmp"
    - "/dev"
    - "/home/sandbox"
    - "/var/lib/agentsh"
  # Everything else is read-only or no-access
```

### Seccomp: Working (including file monitoring)

agentsh's seccomp-bpf filtering works in Firecracker. The `seccomp_user_notify` capability is detected and used for:
- **Execve interception**: Policy-based command blocking at the syscall level
- **File monitoring**: Intercepts `openat`, `unlinkat`, `mkdirat`, `renameat2`, `linkat`, `symlinkat`, `fchmodat`, `fchownat` via `seccomp_unotify`. Reads target paths from process memory (`/proc/[pid]/mem`) and enforces `file_rules` policy. This provides path-based filesystem protection even without Landlock or FUSE.
- **Network monitoring**: Unix socket syscall interception

### Audit Logging: Disabled for Performance

SQLite audit logging (`audit.enabled: true`) causes significant performance degradation in Firecracker due to `fsync()` overhead on the virtual disk. It's disabled in the current config. This is a performance issue, not a capability limitation.

### Server Startup: Pre-warm Required

The agentsh server auto-starts on first `agentsh exec` call. In Firecracker, this takes ~30 seconds (vs <1 second in Docker). The Worker code includes a pre-warm step that starts the server before routing to demo endpoints:

```typescript
if (path.startsWith('/demo/')) {
  await sandbox.exec('agentsh server --config /etc/agentsh/config.yaml &', { timeout: 5000 });
  await sandbox.exec('sleep 2 && agentsh exec --root=/workspace demo -- /bin/bash -c "true"', { timeout: 60000 });
}
```

Without this, the first `agentsh exec` would timeout with the default 30-second `sandbox.exec()` limit.

## Demo Endpoints

| Method | Path | Tests | Description |
|--------|------|-------|-------------|
| GET | `/demo/allowed` | 4 | Safe commands: whoami, pwd, ls, echo |
| GET | `/demo/blocked` | 3 | Policy-blocked: nc, nmap, metadata curl |
| GET | `/demo/devtools` | 10 | Python, Node.js, Bun, git, curl, pip3, pipes |
| GET | `/demo/cloud-metadata` | 6 | AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle |
| GET | `/demo/ssrf` | 9 | RFC 1918 ranges, link-local, external allowed |
| GET | `/demo/filesystem` | 8 | Workspace writes, /etc blocking, soft-delete |
| GET | `/demo/dlp` | 4 | Fake secrets: OpenAI key, AWS key, GitHub PAT |
| GET | `/demo/network` | - | Network blocking overview |
| GET | `/health` | - | Health check (no container needed) |
| POST | `/execute` | - | Execute command (requires Turnstile token) |

**48 automated tests** cover all demo endpoints (`npm test`).

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       Cloudflare Edge                            │
│                                                                  │
│  ┌──────────────────┐      ┌──────────────────────────────────┐  │
│  │  Worker (API)    │      │  Container (Firecracker VM)      │  │
│  │                  │      │                                  │  │
│  │  GET /demo/*  ───┼─────▶│  agentsh v0.9.9                 │  │
│  │  POST /execute   │ exec │  ├─ policy enforcement      ✓   │  │
│  │  GET /health     │      │  ├─ network blocking (eBPF) ✓   │  │
│  │                  │      │  ├─ seccomp-bpf             ✓   │  │
│  │  Rate limiting   │      │  ├─ seccomp file monitor    ✓   │  │
│  │  Turnstile       │      │  ├─ Landlock LSM            ✗   │  │
│  │                  │      │  ├─ FUSE filesystem         ✗   │  │
│  │                  │      │  └─ DLP proxy               ✓   │  │
│  └──────────────────┘      │                                  │  │
│                            │  Python 3.11 / Node.js 20 / Bun │  │
│                            └──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

## Configuration

### Container Image

Based on `cloudflare/sandbox:0.7.2-python` with agentsh v0.9.9 installed via `.deb` package. See `Dockerfile`.

### agentsh Config (`config/agentsh.yaml`)

```yaml
sandbox:
  enabled: true
  allow_degraded: true   # Continue without unavailable kernel features
  fuse:
    enabled: false       # Firecracker seccomp blocks mount()
  network:
    enabled: true
    intercept_mode: "all" # eBPF/proxy network interception
  seccomp:
    enabled: true        # seccomp-bpf works in Firecracker
    file_monitor:
      enabled: true               # Intercept file syscalls via seccomp_unotify
      enforce_without_fuse: true   # Enforce file policy even without FUSE

landlock:
  enabled: true          # Config ready; activates when kernel supports it
  allow_write:
    - "/tmp"
    - "/var/tmp"
    - "/dev"
    - "/home/sandbox"
    - "/var/lib/agentsh"

audit:
  enabled: false         # Disabled - SQLite fsync too slow in Firecracker
```

### Security Policy (`policies/default.yaml`)

Enforces:
- **Network blocking**: Cloud metadata endpoints (AWS, GCP, Azure, DO, Alibaba, Oracle), all RFC 1918 private networks, link-local addresses
- **Command blocking**: `sudo`, `su`, `ssh`, `nc`, `nmap`, `netcat`, etc.
- **File rules**: Workspace and /tmp allowed; system paths blocked (enforced via seccomp file monitor; additionally via Landlock where kernel supports it)

### Wrangler Config (`wrangler.toml`)

- Container: `instance_type = "basic"` (1/4 vCPU, 1GB RAM, 4GB disk)
- Max 3 container instances
- Rate limiting via KV namespace
- Turnstile bot protection on `/execute`

## Development

### Prerequisites

- Node.js 18+
- Docker
- Cloudflare account with Workers Paid plan
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Local Development

```bash
npm install
npm run dev    # Starts wrangler dev with container on localhost:8787
```

### Run Tests

```bash
npm test       # 48 tests across 8 test files (~30s)
```

### Deploy

```bash
npm run deploy
```

**Important**: Cloudflare Containers persist across deploys and don't automatically pick up new images. To force a fresh container:

```bash
# List container apps
npx wrangler containers list

# Delete the old container app (forces recreation on next deploy)
npx wrangler containers delete <app-id>

# Redeploy
npm run deploy
```

Also update the `CACHE_BUST` ARG in `Dockerfile` when config files change, since Docker layer caching may serve stale config.

## Troubleshooting

### Container endpoints timing out

1. **FUSE enabled?** Must be `fuse.enabled: false`. FUSE mount hangs in Firecracker. Filesystem protection uses the seccomp file monitor instead.
2. **Old container image?** Delete container app and redeploy (see Deploy section).
3. **First request slow?** Cold boot takes ~60s. The pre-warm step adds ~30s for first `agentsh exec`.

### Filesystem writes not blocked

Ensure `seccomp.file_monitor.enabled: true` and `seccomp.file_monitor.enforce_without_fuse: true` in `config/agentsh.yaml`. The seccomp file monitor intercepts filesystem syscalls and enforces `file_rules` from the security policy. Landlock provides additional defense-in-depth locally (host kernel ABI v5) but is not available in Firecracker (ABI v0).

### Config changes not taking effect

```bash
docker builder prune -a -f              # Clear Docker cache
# Update CACHE_BUST in Dockerfile
npx wrangler containers delete <app-id>  # Delete old container
npm run deploy                           # Redeploy
```

### "Durable Object reset" errors after deploy

Transient. Wait 1-2 minutes for the DO to stabilize after a deploy.

## License

MIT
