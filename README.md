# agentsh on Cloudflare

Secure AI agent code execution on Cloudflare's edge network using [agentsh](https://github.com/erans/agentsh) for policy enforcement.

## Features

- **Command Blocking** - Blocks dangerous commands (`sudo`, `ssh`, `nc`, `kill`, etc.)
- **Network Control** - Blocks cloud metadata services, private networks, malicious domains
- **DLP Protection** - Redacts API keys, tokens, and sensitive data
- **File Protection** - Soft-deletes for recovery, blocks system file access
- **Web Terminal** - Interactive terminal via ttyd with real-time policy enforcement

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Cloudflare Edge                          │
│  ┌─────────────────┐      ┌─────────────────────────────┐  │
│  │  Worker (API)   │─────▶│  Sandbox Container          │  │
│  │                 │      │                             │  │
│  │  POST /execute  │      │  ┌─────────────────────────┐│  │
│  │  GET /demo/*    │      │  │  agentsh                ││  │
│  │  GET /terminal  │      │  │  ├─ policy enforcement  ││  │
│  │                 │      │  │  ├─ command interception││  │
│  └─────────────────┘      │  │  └─ DLP redaction       ││  │
│                           │  └─────────────────────────┘│  │
│                           │                             │  │
│                           │  ┌─────────────────────────┐│  │
│                           │  │  ttyd (web terminal)    ││  │
│                           │  └─────────────────────────┘│  │
│                           └─────────────────────────────────┘
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Demo web interface |
| POST | `/execute` | Execute command in sandbox |
| GET | `/demo/blocked` | Demo blocked commands |
| GET | `/demo/allowed` | Demo allowed commands |
| GET | `/demo/dlp` | Demo DLP redaction |
| GET | `/terminal` | Get web terminal URL |
| GET | `/health` | Health check |

### Execute Command

```bash
curl -X POST https://your-worker.workers.dev/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "ls -la"}'
```

Response:
```json
{
  "success": true,
  "stdout": "total 0\ndrwxr-xr-x 1 sandbox sandbox ...",
  "stderr": "",
  "exitCode": 0,
  "blocked": false
}
```

### Blocked Command Example

```bash
curl -X POST https://your-worker.workers.dev/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "sudo whoami"}'
```

Response:
```json
{
  "success": false,
  "stdout": "",
  "stderr": "BLOCKED: Privilege escalation via 'sudo' is not allowed",
  "exitCode": 1,
  "blocked": true,
  "message": "Privilege escalation via 'sudo' is not allowed"
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

### 2. Build and push container

```bash
# Set your account ID
export CF_ACCOUNT_ID=your-account-id

# Build
docker build -t agentsh-sandbox .

# Tag for Cloudflare registry
docker tag agentsh-sandbox docker.cloudflare.com/$CF_ACCOUNT_ID/agentsh-sandbox

# Push
docker push docker.cloudflare.com/$CF_ACCOUNT_ID/agentsh-sandbox
```

### 3. Deploy Worker

```bash
npm run deploy
```

## Security Policy

The default policy (`policies/default.yaml`) enforces:

### Blocked Commands
- `sudo`, `su`, `doas`, `pkexec` (privilege escalation)
- `ssh`, `scp`, `sftp`, `rsync` (remote access)
- `nc`, `netcat`, `ncat`, `socat`, `telnet`, `nmap` (network tools)
- `kill`, `killall`, `pkill` (process termination)
- `shutdown`, `reboot`, `systemctl` (system administration)

### Blocked Network Access
- Cloud metadata: `169.254.169.254`, `100.100.100.200`
- Private networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Malicious domains: `evil.com`, `malware.example.com`

### DLP Patterns (Redacted)
- API keys: OpenAI, Anthropic, AWS, GitHub
- PII: Email, phone, credit card, SSN
- Secrets: JWT tokens, private keys, Slack tokens

### Allowed
- Basic shell commands (`ls`, `cat`, `echo`, etc.)
- Development tools (`git`, `python`, `node`, `npm`)
- Package registries (npm, PyPI, GitHub)

## Customization

### Modify Security Policy

Edit `policies/default.yaml` to customize:

```yaml
command_rules:
  - name: block-custom-command
    commands:
      - my-dangerous-command
    decision: deny
    message: "Custom block message"
```

### Adjust Resource Limits

In `config/agentsh.yaml`:

```yaml
resource_limits:
  max_memory_mb: 4096
  cpu_quota_percent: 75
  command_timeout: 5m
```

## Web Terminal

The web terminal provides an interactive shell with real-time agentsh protection:

1. Call `GET /terminal` to get the preview URL
2. Open the URL in your browser
3. Try commands - blocked ones will show `BLOCKED:` messages

## Troubleshooting

### Container not starting
- Check Docker logs: `docker logs <container-id>`
- Verify agentsh server started: Look for "agentsh server started" in logs

### Commands timing out
- Increase timeout in request: `{"command": "...", "timeout": 60000}`
- Check sandbox resource limits in `config/agentsh.yaml`

### Terminal not accessible
- Ensure port 7681 is exposed in Dockerfile
- For production, configure custom domain with wildcard DNS

## License

MIT
