# agentsh on Cloudflare

Proof-of-concept for secure AI agent code execution on Cloudflare's edge network using [agentsh](https://github.com/canyonroad/agentsh).

**Live Demo**: https://agentsh-cloudflare.eran-cf2.workers.dev

## Current Status

This POC demonstrates **agentsh policy enforcement** in Cloudflare Sandbox containers running on Firecracker VMs:

| Feature | Status | Notes |
|---------|--------|-------|
| agentsh installation | ✅ Working | Version 0.9.0 installed |
| Security mode | ✅ Full | 100% protection score detected |
| Policy configuration | ✅ Working | Policies at `/etc/agentsh/policies/` |
| Sandbox API | ✅ Working | Commands via `agentsh exec` |
| Network: Metadata blocking | ✅ Working | Blocks `169.254.169.254`, `100.100.100.200` |
| Network: Private IP blocking | ✅ Working | Blocks `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Network: External access | ✅ Working | Allowed domains accessible |
| File IO blocking | ❌ Not working | FUSE causes container crash (see Limitations) |
| DLP redaction | ❌ Not on stdout | DLP is for API proxy traffic, not command output |
| Web terminal | ❌ Not available | Preview URLs need custom domain |

### Security Capabilities Detected

The Cloudflare Sandbox (Firecracker VM) reports the following kernel capabilities:

```
Security Mode: full
Protection Score: 100%

CAPABILITIES
  capabilities_drop        ✓
  cgroups_v2               ✓
  ebpf                     ✓
  fuse                     ✓ (detected but unusable - see Limitations)
  landlock_abi             ✓ (v0)
  seccomp                  ✓
  seccomp_basic            ✓
  seccomp_user_notify      ✓
  landlock                 -
  landlock_network         -
  pid_namespace            -
```

### How It Works

All commands are executed through `agentsh exec`, which:
1. Auto-starts the agentsh server if not running
2. Applies security policy to each command
3. Blocks network access to forbidden destinations via eBPF/proxy interception
4. Returns policy violation messages for blocked operations

## Limitations

### FUSE / File IO Blocking

While the kernel reports FUSE support (`/dev/fuse` exists), actually mounting a FUSE filesystem causes the Firecracker container to hang and disconnect. This is likely due to:
- Privilege restrictions in Cloudflare's container runtime
- Firecracker VM limitations on FUSE operations

**Impact**: File system interception is not available. Commands can write to any location the user has permissions for (including `/etc/`).

### DLP Redaction

DLP (Data Loss Prevention) is configured but only applies to traffic through the agentsh API proxy, not to command stdout. Echoing API keys or secrets will show them in plain text.

### Web Terminal

The web terminal (ttyd) requires Cloudflare Preview URLs with custom domain and wildcard DNS configuration.

## Features

- **Network Control** - Blocks cloud metadata services, private networks, malicious domains
- **Policy Enforcement** - Commands run through agentsh exec with policy checks
- **eBPF + Seccomp** - Kernel-level security primitives available

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge                          │
│  ┌─────────────────┐      ┌─────────────────────────────┐  │
│  │  Worker (API)   │─────▶│  Sandbox Container          │  │
│  │                 │      │  (Firecracker VM)           │  │
│  │  POST /execute  │      │  ┌─────────────────────────┐│  │
│  │  GET /demo/*    │      │  │  agentsh                ││  │
│  │  GET /health    │      │  │  ├─ policy enforcement  ││  │
│  │                 │      │  │  ├─ network blocking    ││  │
│  └─────────────────┘      │  │  └─ eBPF + seccomp      ││  │
│                           │  └─────────────────────────┘│  │
│                           └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Demo web interface |
| POST | `/execute` | Execute command (requires Turnstile token) |
| GET | `/demo/cloud-metadata` | Multi-cloud metadata protection demo |
| GET | `/demo/ssrf` | SSRF attack prevention demo |
| GET | `/demo/devtools` | Development tools demo |
| GET | `/demo/network` | Network blocking overview |
| GET | `/demo/allowed` | Allowed commands demo |
| GET | `/demo/blocked` | Policy file and blocked commands |
| GET | `/health` | Health check |

### Rate Limiting & Bot Protection

The demo is protected against abuse:
- **Rate limiting**: 10 requests per minute per IP
- **Turnstile**: Cloudflare CAPTCHA required for `/execute` endpoint
- Demo endpoints (`/demo/*`) work without Turnstile but are rate limited

### Demo Endpoints

#### Multi-Cloud Metadata Protection (`/demo/cloud-metadata`)

Demonstrates blocking of instance metadata endpoints across all major cloud providers:
- AWS EC2 (`169.254.169.254`)
- Google Cloud (`metadata.google.internal`)
- Azure IMDS (`169.254.169.254`)
- DigitalOcean (`169.254.169.254`)
- Alibaba Cloud (`100.100.100.200`)
- Oracle Cloud (`169.254.169.254`)

#### SSRF Attack Prevention (`/demo/ssrf`)

Demonstrates blocking of Server-Side Request Forgery attack vectors:
- All RFC 1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
- Link-local addresses (`169.254.0.0/16`)
- Cloud metadata endpoints
- Shows external HTTPS access is allowed for comparison

#### Development Tools (`/demo/devtools`)

Shows that normal development workflows work seamlessly:
- Python 3.11, Node.js 20, Bun 1.3
- Git operations
- External API access (GitHub, httpbin)
- Pipe operations and workspace access

### Execute Command

Requires a valid Turnstile token when called programmatically:

```bash
curl -X POST https://agentsh-cloudflare.eran-cf2.workers.dev/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la", "turnstileToken": "your-token"}'
```

Response:
```json
{
  "success": true,
  "stdout": "total 0\ndrwxr-xr-x 1 root root ...",
  "stderr": "",
  "exitCode": 0,
  "blocked": false
}
```

### Network Blocking Examples

**Cloud metadata (blocked):**
```bash
curl -X POST https://agentsh-cloudflare.eran-cf2.workers.dev/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "curl http://169.254.169.254/"}'
```

Response:
```json
{
  "success": false,
  "stdout": "blocked by policy",
  "stderr": "agentsh: blocked by policy (rule=block-metadata-services)...",
  "exitCode": 0,
  "blocked": true,
  "message": "Blocked by policy: block-metadata-services"
}
```

**Private network (blocked):**
```bash
curl -X POST https://agentsh-cloudflare.eran-cf2.workers.dev/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "curl http://10.0.0.1/"}'
```

Response:
```json
{
  "success": false,
  "stdout": "blocked by policy",
  "stderr": "agentsh: blocked by policy (rule=block-private-networks)...",
  "blocked": true,
  "message": "Blocked by policy: block-private-networks"
}
```

**External site (allowed):**
```bash
curl -X POST https://agentsh-cloudflare.eran-cf2.workers.dev/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "curl -s https://httpbin.org/get | head -3"}'
```

Response:
```json
{
  "success": true,
  "stdout": "{\n  \"args\": {}, \n  \"headers\": {",
  "blocked": false
}
```

## Development Setup

### Prerequisites

- Node.js 18+
- Docker
- Cloudflare account with Workers Paid plan
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Local Development

1. **Install dependencies**
   ```bash
   npm install
   ```

2. **Build the container** (first time only)
   ```bash
   docker build -t agentsh-sandbox .
   ```

3. **Run locally**
   ```bash
   npm run dev
   ```

4. **Open in browser**
   ```
   http://localhost:8787
   ```

## Deployment

### 1. Configure Wrangler

```bash
wrangler login
```

### 2. Deploy (builds and pushes container automatically)

```bash
npm run deploy
```

Note: If config changes aren't deploying, clear Docker cache:
```bash
docker builder prune -a -f
```

Then update `CACHE_BUST` in Dockerfile and redeploy.

## Security Policy

The default policy (`policies/default.yaml`) enforces:

### Blocked Network Access (Working)
- Cloud metadata: `169.254.169.254`, `100.100.100.200`
- Private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Example malicious domains: `evil.com`, `malware.example.com`

### Blocked Commands (Configured but tools not installed)
- `sudo`, `su`, `doas`, `pkexec` (not installed in container)
- `ssh`, `scp`, `sftp`, `rsync` (not installed)
- `nc`, `netcat`, `ncat`, `socat`, `telnet`, `nmap` (not installed)

### Allowed
- Basic shell commands (`ls`, `cat`, `echo`, etc.)
- Development tools (`python`, `node`, `bun`)
- Network access to allowed destinations

## Configuration

### agentsh Config (`config/agentsh.yaml`)

Key settings:
```yaml
server:
  http:
    addr: "127.0.0.1:18080"  # agentsh client default port

sandbox:
  enabled: true
  allow_degraded: true
  fuse:
    enabled: false  # Disabled - causes container crash in Firecracker
  network:
    enabled: true
    intercept_mode: "all"
  cgroups:
    enabled: false  # Read-only in containers
  seccomp:
    enabled: false  # Requires privileged mode
```

### Modify Security Policy

Edit `policies/default.yaml` to customize network rules:

```yaml
network_rules:
  - name: block-custom-domain
    hosts:
      - "*.malicious.com"
    decision: deny
    message: "Access to malicious.com is blocked"
```

## Troubleshooting

### Container disconnecting / commands timing out
- Check if FUSE is enabled in config (should be `false`)
- Increase timeout: `{"command": "...", "timeout": 60000}`

### Config changes not deploying
- Clear Docker cache: `docker builder prune -a -f`
- Update `CACHE_BUST` arg in Dockerfile
- Redeploy: `npm run deploy`

### Network blocking not working
- Verify agentsh exec is wrapping commands (check Worker code)
- Check policy file is correctly mounted at `/etc/agentsh/policies/`

## License

MIT
