# agentsh + Cloudflare Containers

Runtime security governance for AI agents using [agentsh](https://github.com/canyonroad/agentsh) v0.10.4 with [Cloudflare Containers](https://developers.cloudflare.com/containers/) (Firecracker VMs).

## Why agentsh + Cloudflare Containers?

**Cloudflare provides isolation. agentsh provides governance.**

Cloudflare Containers give AI agents a secure, isolated Firecracker VM environment on the edge. But isolation alone doesn't prevent an agent from:

- **Exfiltrating data** to unauthorized endpoints
- **Accessing cloud metadata** (AWS/GCP/Azure credentials at 169.254.169.254)
- **Leaking secrets** in outputs (API keys, tokens, PII)
- **Running dangerous commands** (sudo, ssh, kill, nc)
- **Reaching internal networks** (10.x, 172.16.x, 192.168.x)
- **Deleting workspace files** permanently

agentsh adds the governance layer that controls what agents can do inside the sandbox, providing defense-in-depth:

```
+---------------------------------------------------------+
|  Cloudflare Container (Isolation)                       |
|  +---------------------------------------------------+  |
|  |  agentsh (Governance)                             |  |
|  |  +---------------------------------------------+  |  |
|  |  |  AI Agent                                   |  |  |
|  |  |  - Commands are policy-checked              |  |  |
|  |  |  - Network requests are filtered            |  |  |
|  |  |  - File I/O is policy-enforced              |  |  |
|  |  |  - Secrets are redacted from output         |  |  |
|  |  |  - All actions are audited                  |  |  |
|  |  +---------------------------------------------+  |  |
|  +---------------------------------------------------+  |
+---------------------------------------------------------+
```

## What agentsh Adds

| Cloudflare Provides | agentsh Adds |
|---------------------|--------------|
| Compute isolation (Firecracker) | Command blocking (seccomp) |
| Process sandboxing | File I/O policy (Landlock + permissions) |
| API access to sandbox | Domain allowlist/blocklist |
| Persistent environment | Cloud metadata blocking |
| | Environment variable filtering |
| | Secret detection and redaction (DLP) |
| | Landlock filesystem restrictions |
| | LLM request auditing |
| | Complete audit logging |

## Quick Start

### Prerequisites

- Node.js 18+
- Docker
- Cloudflare account with Workers Paid plan
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Install and Test

```bash
git clone https://github.com/canyonroad/agentsh-cloudflare
cd agentsh-cloudflare
npm install

# Local development (starts wrangler dev with container)
npm run dev

# Run the full test suite (71 tests)
npm test
```

## How It Works

The Cloudflare Worker wraps every command with `agentsh exec` before passing it to the container's `sandbox.exec()` API:

```
Worker: sandbox.exec("agentsh exec --root=/workspace demo -- /bin/bash -c 'sudo whoami'")
                     |
                     v
            +-------------------+
            |  agentsh exec     |  CLI sends to agentsh server
            |  (intercepts)     |
            +--------+----------+
                     |
                     v
            +-------------------+
            |  agentsh server   |  Policy evaluation + Landlock
            |  (pre-warmed)     |  + seccomp enforcement
            +--------+----------+
                     |
              +------+------+
              v             v
        +----------+  +----------+
        |  ALLOW   |  |  BLOCK   |
        | exit: 0  |  | exit: 1  |
        +----------+  +----------+
```

The agentsh server is pre-warmed via an `/internal/start-agentsh` endpoint during test setup, and via systemd/rc.local on container boot. This avoids the cold-start penalty on first exec.

## Capabilities on Cloudflare Containers

| Capability | Status | Notes |
|------------|--------|-------|
| seccomp | Working | Full seccomp including `seccomp_user_notify` |
| seccomp_user_notify | Working | Key feature for syscall interception (kernel 5.0+) |
| Landlock | Working (local) | ABI v5 locally via host kernel; production kernel TBD |
| cgroups_v2 | Working | Full controllers |
| ebpf | Working | Network interception |
| capabilities_drop | Working | Available |
| FUSE | Not available | Firecracker seccomp blocks `mount()` syscall |
| seccomp file_monitor | Disabled | agentsh bug: notify handler panic causes EOF with bash |
| pid_namespace | Not available | Not available in Firecracker config |

## For Cloudflare Engineers: What to Enable

This section describes what Cloudflare can enable on their infrastructure to unlock full agentsh protection.

### FUSE (`/dev/fuse`) -- High Impact

**Current state**: The Firecracker VM has `CAP_SYS_ADMIN` and `fusermount3` is installed, but the Firecracker seccomp profile blocks the `mount()` syscall. When agentsh tries to set up a FUSE overlay filesystem, the mount call hangs indefinitely, making the server unresponsive.

**What it unlocks**:
- **VFS-level file interception** -- agentsh mounts a FUSE overlay on the workspace, intercepting every `open()`, `write()`, `unlink()`, `mkdir()` at the filesystem level. This is far more comprehensive than permission-based blocking.
- **Soft-delete quarantine** -- When an agent runs `rm`, the file is moved to a quarantine directory instead of being deleted. Files can be listed with `agentsh trash list` and restored with `agentsh trash restore`.
- **Symlink escape prevention** -- FUSE intercepts symlink traversal, blocking agents from creating symlinks to sensitive paths like `/etc/shadow`.
- **Credential file blocking** -- FUSE can block reads to `~/.ssh/id_rsa`, `~/.aws/credentials`, `/proc/1/environ` regardless of Unix permissions.

**How to enable**: Allow the `mount()` syscall in the Firecracker seccomp profile, or expose `/dev/fuse` (character device 10,229) with appropriate permissions. This is a standard Firecracker configuration -- other Firecracker-based platforms (E2B, etc.) expose it by default.

### seccomp file_monitor -- Known agentsh Bug

**Current state**: agentsh's seccomp file_monitor uses `seccomp_unotify` to intercept file syscalls (`openat`, `unlinkat`, `mkdirat`, etc.) and enforce file access policy. When `/bin/bash` runs under this interception, the HTTP exec handler returns EOF. The server process stays alive (health check passes), but the notify handler goroutine dies silently.

**Root cause**: The seccomp notify handler goroutine in `internal/api/notify_linux.go:124` has no `defer recover()`. When bash generates a burst of file syscall notifications during startup (reading `/etc/bash.bashrc`, `/etc/profile`, shared libraries), a panic in `handleFileNotification` kills the goroutine. Tracee processes block forever waiting for seccomp responses, causing the exec to hang and return EOF. Tested on both `basic` (0.25 vCPU) and `standard-2` (1 vCPU) -- same behavior, confirming this is **not a resource issue**.

**Current workaround**: `seccomp.file_monitor.enabled: false`. Landlock (ABI v5) provides kernel-level filesystem protection.

**Fix needed in agentsh**: Add panic recovery to the notify handler goroutine, log panics with stack traces, and send EACCES responses to unblock tracee processes after recovery.

### PID Namespace -- Low Impact

**Current state**: PID namespace creation is not available.

**What it unlocks**:
- **Process isolation** -- agentsh can create sessions in isolated PID namespaces, preventing agents from seeing or signaling other processes.

**How to enable**: Allow `CLONE_NEWPID` in the Firecracker seccomp filter, or configure PID namespace support in the VM.

### Summary

| Feature | Impact | Current | What's Needed |
|---------|--------|---------|---------------|
| FUSE | **High** -- enables file interception, soft-delete, symlink protection | Blocked (`mount()` denied) | Allow `mount()` in Firecracker seccomp |
| seccomp file_monitor | Medium -- dual-layer filesystem protection | agentsh bug (notify panic) | Fix in agentsh: add panic recovery |
| PID namespace | Low -- process isolation | Not available | Allow `CLONE_NEWPID` |

With FUSE enabled, protection would increase from ~80% to ~95%.

## Configuration

Security policy is defined in two files:

- **`config/agentsh.yaml`** -- Server configuration: network interception, [DLP patterns](https://www.agentsh.org/docs/#llm-proxy), LLM proxy, [FUSE settings](https://www.agentsh.org/docs/#fuse), [Landlock](https://www.agentsh.org/docs/#landlock), [seccomp](https://www.agentsh.org/docs/#seccomp)
- **`policies/default.yaml`** -- [Policy rules](https://www.agentsh.org/docs/#policy-reference): [command rules](https://www.agentsh.org/docs/#command-rules), [network rules](https://www.agentsh.org/docs/#network-rules), [file rules](https://www.agentsh.org/docs/#file-rules)

See the [agentsh documentation](https://www.agentsh.org/docs/) for the full policy reference.

## Project Structure

```
agentsh-cloudflare/
├── src/index.ts             # Cloudflare Worker (API routes, agentsh exec wrapping)
├── Dockerfile               # Container image with agentsh v0.10.4
├── config/agentsh.yaml      # Server config (Landlock, seccomp, DLP, network)
├── policies/default.yaml    # Security policy (commands, network, files)
├── systemd/agentsh.service  # Systemd service for agentsh server
├── scripts/rc.local         # Fallback startup script
├── wrangler.toml            # Cloudflare Workers + Containers config
├── vitest.config.ts         # Test configuration
└── test/                    # Integration tests (71 tests, 11 categories)
    ├── global-setup.ts      # Test warmup (container + server + exec path)
    ├── helpers/              # Test utilities (fetchDemo, findResult)
    ├── agentsh-installation.test.ts
    ├── agentsh-status.test.ts
    ├── allowed-commands.test.ts
    ├── blocked-commands.test.ts
    ├── cloud-metadata.test.ts
    ├── command-blocking.test.ts
    ├── devtools.test.ts
    ├── dlp-redaction.test.ts
    ├── filesystem.test.ts
    ├── privilege-escalation.test.ts
    └── ssrf-prevention.test.ts
```

## Testing

The test suite creates a Cloudflare Container and runs 71 security tests across 11 categories:

- **Installation** -- agentsh binary, version, config directory, security capabilities
- **Status** -- agentsh detect, kernel version, policy files, seccomp status
- **Allowed commands** -- whoami, pwd, ls, echo through agentsh enforcement
- **Blocked commands** -- nc, nmap, cloud metadata curl
- **Command blocking** -- sudo, su, ssh, scp, shutdown, mount, nc, nmap, killall, pkill
- **Privilege escalation** -- sudo id, sudo cat shadow, su root, pkexec, shadow read, sudoers write
- **Filesystem protection** -- workspace writes allowed; /etc/passwd, /etc/shadow, /usr/bin, config overwrite blocked
- **Cloud metadata** -- AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle metadata endpoints blocked
- **SSRF prevention** -- All RFC 1918 ranges, link-local addresses blocked; external HTTPS allowed
- **Dev tools** -- Python, Node.js, Bun, git, curl, pip3, pipes all working
- **DLP redaction** -- Fake OpenAI key, AWS key, GitHub PAT, email/phone detection

```bash
npm test       # 71 tests across 11 files (~10s with warm sandbox)
```

## Demo Endpoints

| Method | Path | Tests | Description |
|--------|------|-------|-------------|
| GET | `/demo/allowed` | 4 | Safe commands: whoami, pwd, ls, echo |
| GET | `/demo/blocked` | 3 | Policy-blocked: nc, nmap, metadata curl |
| GET | `/demo/commands` | 10 | Full command blocking: sudo, su, ssh, scp, shutdown, mount, nc, nmap, killall, pkill |
| GET | `/demo/privilege-escalation` | 6 | Privilege escalation prevention |
| GET | `/demo/filesystem` | 8 | Filesystem protection (Landlock) |
| GET | `/demo/cloud-metadata` | 6 | AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle |
| GET | `/demo/ssrf` | 9 | RFC 1918 ranges, link-local, external allowed |
| GET | `/demo/devtools` | 10 | Python, Node.js, Bun, git, curl, pip3, pipes |
| GET | `/demo/dlp` | 4 | Fake secrets: OpenAI key, AWS key, GitHub PAT |
| GET | `/demo/network` | - | Network blocking overview |
| GET | `/demo/status` | 7 | agentsh installation and security status |
| GET | `/health` | - | Health check (no container needed) |
| POST | `/execute` | - | Execute command (requires Turnstile token) |

## Deploy

```bash
npm run deploy
```

**Important**: Cloudflare Containers persist across deploys and don't automatically pick up new images. To force a fresh container:

```bash
npx wrangler containers list
npx wrangler containers delete <app-id>
npm run deploy
```

Update the `CACHE_BUST` ARG in `Dockerfile` when config files change, since Docker layer caching may serve stale config.

## Cloudflare Container Environment

| Property | Value |
|----------|-------|
| Base Image | `cloudflare/sandbox:0.7.2-python` |
| VM Type | Firecracker (`basic`: 0.25 vCPU, 1GB RAM, 4GB disk) |
| Python | 3.11 |
| Node.js | 20 |
| Bun | Available |
| agentsh | v0.10.4 (`.deb` package) |
| Workspace | `/workspace` |

## Related Projects

- [agentsh](https://github.com/canyonroad/agentsh) -- Runtime security for AI agents ([docs](https://www.agentsh.org/docs/))
- [agentsh + E2B](https://github.com/canyonroad/e2b-agentsh) -- agentsh integration with E2B sandboxes
- [agentsh + Daytona](https://github.com/canyonroad/agentsh-daytona) -- agentsh integration with Daytona sandboxes
- [agentsh + Vercel](https://github.com/canyonroad/agentsh-vercel) -- agentsh integration with Vercel Sandbox
- [Cloudflare Containers](https://developers.cloudflare.com/containers/) -- Cloudflare's container platform

## License

MIT
