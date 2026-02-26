/**
 * Cloudflare Worker with agentsh-protected Sandbox
 *
 * Demonstrates secure AI agent code execution with:
 * - Command blocking (sudo, ssh, nc, etc.)
 * - Network control (blocks metadata services, private networks)
 * - Rate limiting and Turnstile protection
 */

import { getSandbox, type Sandbox, type ExecResult } from "@cloudflare/sandbox";

// Re-export Sandbox class for Durable Objects
export { Sandbox } from "@cloudflare/sandbox";

type Env = {
  SANDBOX: DurableObjectNamespace<Sandbox>;
  RATE_LIMIT: KVNamespace;
  ENVIRONMENT: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
};

// Type for the sandbox instance returned by getSandbox
type SandboxInstance = ReturnType<typeof getSandbox>;

interface ExecuteRequest {
  command: string;
  timeout?: number;
  turnstileToken?: string;
}

interface ExecuteResponse {
  success: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  blocked?: boolean;
  message?: string;
}

interface DemoResult {
  command: string;
  result: ExecuteResponse;
}

// Rate limiting config
const RATE_LIMIT_WINDOW = 60; // seconds
const RATE_LIMIT_MAX = 10; // requests per window

// Get client IP from request
function getClientIP(request: Request): string {
  return request.headers.get('CF-Connecting-IP') ||
         request.headers.get('X-Forwarded-For')?.split(',')[0] ||
         'unknown';
}

// Check rate limit
async function checkRateLimit(env: Env, ip: string): Promise<{ allowed: boolean; remaining: number }> {
  const key = `rate:${ip}`;
  const now = Math.floor(Date.now() / 1000);
  const windowStart = now - (now % RATE_LIMIT_WINDOW);
  const windowKey = `${key}:${windowStart}`;

  const countStr = await env.RATE_LIMIT.get(windowKey);
  const count = countStr ? parseInt(countStr, 10) : 0;

  if (count >= RATE_LIMIT_MAX) {
    return { allowed: false, remaining: 0 };
  }

  // Increment count
  await env.RATE_LIMIT.put(windowKey, String(count + 1), {
    expirationTtl: RATE_LIMIT_WINDOW * 2,
  });

  return { allowed: true, remaining: RATE_LIMIT_MAX - count - 1 };
}

// Verify Turnstile token
async function verifyTurnstile(token: string, ip: string, secretKey: string): Promise<boolean> {
  if (!secretKey) {
    // Skip verification if no secret key configured (development mode)
    return true;
  }

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      secret: secretKey,
      response: token,
      remoteip: ip,
    }),
  });

  const result = await response.json() as { success: boolean };
  return result.success;
}

// HTML template for the demo page - matches agentsh.org branding
function getHtmlTemplate(turnstileSiteKey: string): string {
  const turnstileEnabled = !!turnstileSiteKey;
  const utmAgentsh = 'utm_source=cloudflare-demo&utm_medium=web&utm_campaign=agentsh-demo';
  const utmCanyonRoad = 'utm_source=agentsh-cloudflare-demo&utm_medium=web&utm_campaign=agentsh-demo';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>agentsh Live Demo - Secure AI Agent Execution on Cloudflare</title>
  <meta name="description" content="Try agentsh live on Cloudflare. See syscall-level enforcement block dangerous commands and network access in real-time.">
  <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect width='24' height='24' rx='4' fill='%232D6A4F'/><polyline points='5 16 10 11 5 6' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/><line x1='12' y1='18' x2='19' y2='18' stroke='white' stroke-width='2' stroke-linecap='round'/></svg>" type="image/svg+xml">
  <link rel="apple-touch-icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><rect width='24' height='24' rx='4' fill='%232D6A4F'/><polyline points='5 16 10 11 5 6' fill='none' stroke='white' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'/><line x1='12' y1='18' x2='19' y2='18' stroke='white' stroke-width='2' stroke-linecap='round'/></svg>">
  <meta property="og:image" content="https://www.agentsh.org/og-image.png">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  ${turnstileEnabled ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ''}
  <style>
    :root {
      --evergreen: #0E4A33;
      --moss: #4FA36A;
      --river: #1A8890;
      --mist: #F4F8F6;
      --white: #ffffff;
      --pine-black: #06100C;
      --deep-fir: #0A2A1F;
      --clay: #C86A3E;
      --sunlit: #E2B84A;
      --border-subtle: #e2e8e5;
      --terminal-bg: #0a1612;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--mist);
      color: var(--pine-black);
      line-height: 1.6;
      min-height: 100vh;
    }
    .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }

    /* Header */
    .header {
      text-align: center;
      margin-bottom: 48px;
    }
    .logo-link {
      display: inline-flex;
      align-items: center;
      gap: 12px;
      text-decoration: none;
      margin-bottom: 16px;
    }
    .logo-mark {
      width: 48px;
      height: 48px;
      border-radius: 12px;
      background: var(--evergreen);
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .logo-mark svg {
      width: 28px;
      height: 28px;
    }
    .logo-text {
      font-family: 'DM Serif Display', serif;
      font-size: 32px;
      color: var(--pine-black);
    }
    h1 {
      font-family: 'DM Serif Display', serif;
      font-size: 42px;
      color: var(--pine-black);
      margin-bottom: 12px;
      font-weight: 400;
    }
    .subtitle {
      font-size: 18px;
      color: var(--deep-fir);
      opacity: 0.8;
      max-width: 600px;
      margin: 0 auto 8px;
    }
    .powered-by {
      font-size: 14px;
      color: var(--deep-fir);
      opacity: 0.6;
    }
    .powered-by a {
      color: var(--evergreen);
      text-decoration: none;
      font-weight: 500;
    }
    .powered-by a:hover { text-decoration: underline; }

    /* Feature Grid */
    .feature-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 40px;
    }
    .feature {
      background: var(--white);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 20px;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .feature:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px rgba(14, 74, 51, 0.08);
    }
    .feature h3 {
      font-family: 'DM Serif Display', serif;
      font-size: 18px;
      color: var(--evergreen);
      margin-bottom: 8px;
      font-weight: 400;
    }
    .feature p {
      font-size: 14px;
      color: var(--deep-fir);
      opacity: 0.8;
    }

    /* Terminal Card */
    h2 {
      font-family: 'DM Serif Display', serif;
      font-size: 28px;
      color: var(--pine-black);
      margin-bottom: 16px;
      font-weight: 400;
    }
    .card {
      background: var(--white);
      border: 1px solid var(--border-subtle);
      border-radius: 16px;
      padding: 24px;
      margin-bottom: 32px;
      box-shadow: 0 4px 16px rgba(14, 74, 51, 0.04);
    }
    .input-row {
      display: flex;
      gap: 12px;
      margin-bottom: 16px;
    }
    #command {
      flex: 1;
      padding: 12px 16px;
      background: var(--mist);
      border: 1px solid var(--border-subtle);
      color: var(--pine-black);
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
    }
    #command:focus {
      outline: none;
      border-color: var(--evergreen);
      box-shadow: 0 0 0 3px rgba(14, 74, 51, 0.1);
    }
    #command::placeholder { color: var(--deep-fir); opacity: 0.5; }

    .btn {
      background: var(--evergreen);
      color: var(--white);
      border: none;
      padding: 12px 24px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: 600;
      font-size: 14px;
      transition: background 0.2s, transform 0.1s;
    }
    .btn:hover { background: var(--deep-fir); }
    .btn:active { transform: scale(0.98); }
    .btn:disabled { background: var(--border-subtle); cursor: not-allowed; color: var(--deep-fir); }
    .btn-secondary {
      background: var(--mist);
      color: var(--evergreen);
      border: 1px solid var(--border-subtle);
    }
    .btn-secondary:hover { background: var(--white); border-color: var(--evergreen); }

    .button-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }

    .turnstile-container { margin: 16px 0; }
    .warning {
      color: var(--sunlit);
      font-size: 14px;
      background: rgba(226, 184, 74, 0.1);
      padding: 8px 12px;
      border-radius: 6px;
      margin: 12px 0;
    }
    .rate-limit-info {
      font-size: 13px;
      color: var(--deep-fir);
      opacity: 0.6;
      margin-bottom: 16px;
    }

    /* Terminal Output */
    .output-label {
      font-size: 13px;
      font-weight: 600;
      color: var(--deep-fir);
      margin-bottom: 8px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    #output {
      background: var(--terminal-bg);
      color: #e0e6e3;
      padding: 20px;
      border-radius: 12px;
      min-height: 200px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      white-space: pre-wrap;
      overflow-x: auto;
      border: 1px solid rgba(79, 163, 106, 0.2);
    }
    #output .blocked { color: var(--clay); }
    #output .allowed { color: var(--moss); }
    #output .denied { color: var(--sunlit); }

    /* API Section */
    .endpoint {
      background: var(--mist);
      padding: 12px 16px;
      border-radius: 8px;
      margin: 12px 0;
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
    }
    .method { color: var(--moss); font-weight: 600; }
    .path { color: var(--river); }
    code {
      background: var(--mist);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 13px;
      color: var(--evergreen);
    }

    /* Footer */
    .footer {
      text-align: center;
      padding: 40px 20px;
      border-top: 1px solid var(--border-subtle);
      margin-top: 40px;
    }
    .footer-links {
      display: flex;
      justify-content: center;
      gap: 24px;
      margin-bottom: 16px;
      flex-wrap: wrap;
    }
    .footer-links a {
      color: var(--evergreen);
      text-decoration: none;
      font-weight: 500;
      font-size: 14px;
    }
    .footer-links a:hover { text-decoration: underline; }
    .footer-credit {
      font-size: 14px;
      color: var(--deep-fir);
      opacity: 0.6;
    }
    .footer-credit a {
      color: var(--evergreen);
      text-decoration: none;
      font-weight: 500;
    }
    .footer-credit a:hover { text-decoration: underline; }

    @media (max-width: 600px) {
      h1 { font-size: 32px; }
      .input-row { flex-direction: column; }
      .btn { width: 100%; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <a href="https://www.agentsh.org?${utmAgentsh}" class="logo-link">
        <div class="logo-mark">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="4 17 10 11 4 5"></polyline>
            <line x1="12" y1="19" x2="20" y2="19"></line>
          </svg>
        </div>
        <span class="logo-text">agentsh</span>
      </a>
      <h1>Live Demo on Cloudflare</h1>
      <p class="subtitle">See syscall-level enforcement in action. Try to access cloud metadata, private networks, or run blocked commands.</p>
      <p class="powered-by">Running on Cloudflare Workers + Sandbox</p>
    </header>

    <div class="feature-grid">
      <div class="feature">
        <h3>Network Blocking</h3>
        <p>Blocks cloud metadata (169.254.169.254), private networks, and malicious domains</p>
      </div>
      <div class="feature">
        <h3>eBPF + Seccomp</h3>
        <p>Kernel-level enforcement that can't be bypassed by prompt injection</p>
      </div>
      <div class="feature">
        <h3>Policy Engine</h3>
        <p>Configurable rules for commands, network, and file access</p>
      </div>
      <div class="feature">
        <h3>100% Protection</h3>
        <p>Full security mode with syscall interception enabled</p>
      </div>
      <div class="feature">
        <h3>Command Blocking</h3>
        <p>Blocks sudo, ssh, nc, nmap, kill, and 50+ dangerous commands by policy</p>
      </div>
    </div>

    <h2>Try It Live</h2>
    <div class="card">
      <div class="input-row">
        <input type="text" id="command" placeholder="curl http://169.254.169.254/latest/meta-data/">
        <button class="btn" id="executeBtn" onclick="executeCommand()" ${turnstileEnabled ? 'disabled' : ''}>Execute</button>
      </div>

      ${turnstileEnabled ? `
      <div class="turnstile-container">
        <div class="cf-turnstile" data-sitekey="${turnstileSiteKey}" data-callback="onTurnstileSuccess" data-theme="light"></div>
      </div>
      ` : '<p class="warning">Turnstile not configured - running in development mode</p>'}

      <div class="button-row">
        <button class="btn btn-secondary" onclick="runDemo('cloud-metadata')">Multi-Cloud Metadata</button>
        <button class="btn btn-secondary" onclick="runDemo('ssrf')">SSRF Prevention</button>
        <button class="btn btn-secondary" onclick="runDemo('filesystem')">File Protection</button>
        <button class="btn btn-secondary" onclick="runDemo('devtools')">Dev Tools</button>
        <button class="btn btn-secondary" onclick="runDemo('network')">Network Blocking</button>
        <button class="btn btn-secondary" onclick="runDemo('commands')">Command Blocking</button>
        <button class="btn btn-secondary" onclick="runDemo('privilege-escalation')">Privilege Escalation</button>
        <button class="btn btn-secondary" onclick="runDemo('status')">agentsh Status</button>
      </div>

      <p class="rate-limit-info">Rate limit: <span id="remaining">${RATE_LIMIT_MAX}</span> requests remaining (resets every ${RATE_LIMIT_WINDOW}s)</p>

      <div class="output-label">Output</div>
      <div id="output">Ready to execute commands...

Try these examples:
  $ curl http://169.254.169.254/    # Cloud metadata - BLOCKED
  $ curl http://10.0.0.1/           # Private network - BLOCKED
  $ curl https://httpbin.org/get    # External site - ALLOWED
  $ whoami                          # Basic command - ALLOWED</div>
    </div>

    <h2>API Reference</h2>
    <div class="card">
      <div class="endpoint">
        <span class="method">POST</span> <span class="path">/execute</span>
      </div>
      <p>Execute a command in the sandbox. Requires Turnstile verification.</p>
      <p style="margin-top: 8px;"><code>{"command": "...", "turnstileToken": "..."}</code></p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/cloud-metadata</span>
      </div>
      <p>Multi-cloud metadata protection (AWS, GCP, Azure, DigitalOcean, Alibaba, Oracle)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/ssrf</span>
      </div>
      <p>SSRF prevention (localhost, loopback, private networks, link-local)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/devtools</span>
      </div>
      <p>Development tools demo (Python, Node.js, Bun, Git, external APIs)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/network</span>
      </div>
      <p>Network blocking overview (blocked vs allowed)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/filesystem</span>
      </div>
      <p>Filesystem protection (seccomp file monitor, write blocking, sensitive file access)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/commands</span>
      </div>
      <p>Command blocking (10 commands across privilege escalation, SSH, system admin, network tools, process control)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/privilege-escalation</span>
      </div>
      <p>Privilege escalation prevention (command-level + file-level blocking)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/status</span>
      </div>
      <p>agentsh status and configuration (version, capabilities, policy info)</p>
    </div>
  </div>

  <footer class="footer">
    <div class="footer-links">
      <a href="https://www.agentsh.org?${utmAgentsh}">agentsh.org</a>
      <a href="https://www.agentsh.org/docs?${utmAgentsh}">Documentation</a>
      <a href="https://github.com/canyonroad/agentsh?${utmAgentsh}">GitHub</a>
      <a href="https://github.com/canyonroad/agentsh-cloudflare?${utmAgentsh}">This Demo's Source</a>
    </div>
    <p class="footer-credit">by <a href="https://www.canyonroad.ai?${utmCanyonRoad}">Canyon Road</a></p>
  </footer>

  <script>
    let turnstileToken = ${turnstileEnabled ? 'null' : '"dev-mode"'};

    function onTurnstileSuccess(token) {
      turnstileToken = token;
      document.getElementById('executeBtn').disabled = false;
    }

    async function executeCommand() {
      const command = document.getElementById('command').value;
      const output = document.getElementById('output');

      if (!command) {
        output.textContent = 'Please enter a command';
        return;
      }

      if (!turnstileToken) {
        output.textContent = 'Please complete the verification challenge first';
        return;
      }

      output.textContent = 'Executing...';

      try {
        const res = await fetch('/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command, turnstileToken })
        });

        const remaining = res.headers.get('X-RateLimit-Remaining');
        if (remaining) {
          document.getElementById('remaining').textContent = remaining;
        }

        if (res.status === 429) {
          output.innerHTML = '<span class="blocked">Rate limit exceeded. Please wait and try again.</span>';
          return;
        }

        if (res.status === 403) {
          output.innerHTML = '<span class="blocked">Verification failed. Please refresh and try again.</span>';
          if (typeof turnstile !== 'undefined') {
            turnstile.reset();
            turnstileToken = null;
            document.getElementById('executeBtn').disabled = true;
          }
          return;
        }

        const data = await res.json();
        output.innerHTML = formatResult(command, data);
      } catch (e) {
        output.textContent = 'Error: ' + e.message;
      }
    }

    async function runDemo(type) {
      const output = document.getElementById('output');
      output.textContent = 'Running demo...';

      try {
        const res = await fetch('/demo/' + type);

        const remaining = res.headers.get('X-RateLimit-Remaining');
        if (remaining) {
          document.getElementById('remaining').textContent = remaining;
        }

        if (res.status === 429) {
          output.innerHTML = '<span class="blocked">Rate limit exceeded. Please wait and try again.</span>';
          return;
        }

        const data = await res.json();
        output.innerHTML = data.results.map(r => formatResult(r.command, r.result)).join('\\n\\n');
      } catch (e) {
        output.textContent = 'Error: ' + e.message;
      }
    }

    function formatResult(command, result) {
      let status;
      if (result.blocked) {
        status = '<span class="blocked">BLOCKED</span>';
      } else if (result.success) {
        status = '<span class="allowed">OK</span>';
      } else {
        status = '<span class="denied">DENIED</span>';
      }
      let output = '$ ' + escapeHtml(command) + '  [' + status + ']\\n';
      if (result.stdout) output += escapeHtml(result.stdout) + '\\n';
      if (result.stderr) output += '<span class="blocked">' + escapeHtml(result.stderr) + '</span>\\n';
      if (result.message) output += '<span class="blocked">' + escapeHtml(result.message) + '</span>\\n';
      return output;
    }

    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }

    document.getElementById('command').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') executeCommand();
    });
  </script>
</body>
</html>`;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const clientIP = getClientIP(request);

    // CORS headers
    const headers: Record<string, string> = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    // Check rate limit for all non-health endpoints (skip in development)
    if (path !== '/health' && env.ENVIRONMENT !== 'development') {
      const rateLimit = await checkRateLimit(env, clientIP);
      headers['X-RateLimit-Remaining'] = String(rateLimit.remaining);
      headers['X-RateLimit-Limit'] = String(RATE_LIMIT_MAX);

      if (!rateLimit.allowed) {
        return Response.json(
          { error: 'Rate limit exceeded', retryAfter: RATE_LIMIT_WINDOW },
          { status: 429, headers }
        );
      }
    }

    try {
      // Get sandbox instance (shared across requests for demo)
      const sandbox = getSandbox(env.SANDBOX, 'demo-sandbox-v2');

      // Route handling
      if (path === '/' || path === '') {
        return new Response(getHtmlTemplate(env.TURNSTILE_SITE_KEY || ''), {
          headers: { ...headers, 'Content-Type': 'text/html' },
        });
      }

      if (path === '/execute' && request.method === 'POST') {
        return await handleExecute(request, env, sandbox, clientIP, headers);
      }

      if (path === '/demo/blocked') {
        return await handleDemoBlocked(sandbox, headers);
      }

      if (path === '/demo/allowed') {
        return await handleDemoAllowed(sandbox, headers);
      }

      if (path === '/demo/dlp') {
        return await handleDemoDLP(sandbox, headers);
      }

      if (path === '/demo/network') {
        return await handleDemoNetwork(sandbox, headers);
      }

      if (path === '/demo/cloud-metadata') {
        return await handleDemoCloudMetadata(sandbox, headers);
      }

      if (path === '/demo/ssrf') {
        return await handleDemoSSRF(sandbox, headers);
      }

      if (path === '/demo/devtools') {
        return await handleDemoDevTools(sandbox, headers);
      }

      if (path === '/demo/filesystem') {
        return await handleDemoFilesystem(sandbox, headers);
      }

      if (path === '/demo/commands') {
        return await handleDemoCommands(sandbox, headers);
      }

      if (path === '/demo/privilege-escalation') {
        return await handleDemoPrivilegeEscalation(sandbox, headers);
      }

      if (path === '/demo/status') {
        return await handleDemoStatus(sandbox, headers);
      }

      if (path === '/internal/start-agentsh') {
        return await handleStartAgentsh(sandbox, headers);
      }

      if (path === '/terminal') {
        return await handleTerminal(sandbox, headers);
      }

      if (path === '/health') {
        return Response.json({ status: 'ok' }, { headers });
      }

      return Response.json({ error: 'Not found' }, { status: 404, headers });

    } catch (error) {
      console.error('Error:', error);
      return Response.json(
        { error: 'Internal server error', details: String(error) },
        { status: 500, headers }
      );
    }
  },
};

async function handleExecute(
  request: Request,
  env: Env,
  sandbox: SandboxInstance,
  clientIP: string,
  headers: Record<string, string>
): Promise<Response> {
  const body = await request.json() as ExecuteRequest;

  if (!body.command) {
    return Response.json({ error: 'Missing command' }, { status: 400, headers });
  }

  // Verify Turnstile token (skip if not configured)
  if (env.TURNSTILE_SECRET_KEY) {
    if (!body.turnstileToken) {
      return Response.json({ error: 'Missing Turnstile token' }, { status: 403, headers });
    }

    const isValid = await verifyTurnstile(body.turnstileToken, clientIP, env.TURNSTILE_SECRET_KEY);
    if (!isValid) {
      return Response.json({ error: 'Invalid Turnstile token' }, { status: 403, headers });
    }
  }

  const result = await executeInSandbox(sandbox, body.command, body.timeout);

  return Response.json(result, { headers });
}

async function handleDemoBlocked(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // Run policy display and blocked commands with limited concurrency
  const [policyResult, ...blockedResults] = await runParallel([
    () => executeRaw(sandbox, 'cat /etc/agentsh/policies/default.yaml | head -50'),
    () => executeInSandbox(sandbox, 'nc -h'),
    () => executeInSandbox(sandbox, 'nmap --version'),
    () => executeInSandbox(sandbox, 'curl http://169.254.169.254/latest/meta-data/'),
  ]);

  const results: DemoResult[] = [
    { command: 'Policy file (head -50)', result: policyResult },
    { command: 'nc -h (network tool blocked)', result: blockedResults[0] },
    { command: 'nmap --version (network scanner blocked)', result: blockedResults[1] },
    { command: 'curl http://169.254.169.254/latest/meta-data/ (cloud metadata blocked)', result: blockedResults[2] },
  ];

  return Response.json({
    description: 'agentsh policy enforcement is ACTIVE. These commands are blocked by policy.',
    note: 'Commands are executed through agentsh exec which enforces the security policy.',
    policyPath: '/etc/agentsh/policies/default.yaml',
    results
  }, { headers });
}

async function handleDemoAllowed(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // Run all checks with limited concurrency
  const [agentshVersion, agentshLocation, configCheck, detectResult,
         whoamiResult, pwdResult, lsResult, echoResult] = await runParallel([
    () => executeRaw(sandbox, 'agentsh --version'),
    () => executeRaw(sandbox, 'which agentsh'),
    () => executeRaw(sandbox, 'ls -la /etc/agentsh/'),
    () => executeRaw(sandbox, 'agentsh detect 2>&1 | head -20'),
    () => executeInSandbox(sandbox, 'whoami'),
    () => executeInSandbox(sandbox, 'pwd'),
    () => executeInSandbox(sandbox, 'ls -la /workspace'),
    () => executeInSandbox(sandbox, 'echo "Hello from agentsh sandbox!"'),
  ]);

  const results: DemoResult[] = [
    { command: 'agentsh --version', result: agentshVersion },
    { command: 'which agentsh', result: agentshLocation },
    { command: 'ls -la /etc/agentsh/', result: configCheck },
    { command: 'agentsh detect (security capabilities)', result: detectResult },
    { command: 'whoami', result: whoamiResult },
    { command: 'pwd', result: pwdResult },
    { command: 'ls -la /workspace', result: lsResult },
    { command: 'echo "Hello from agentsh sandbox!"', result: echoResult },
  ];

  return Response.json({
    description: 'agentsh is installed with full security capabilities. These commands are allowed by policy.',
    note: 'All user commands go through agentsh exec for policy enforcement.',
    results
  }, { headers });
}

async function handleDemoDLP(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // These contain fake secrets that should be redacted by DLP
  const dlpCommands = [
    'echo "OpenAI key: sk-1234567890abcdef1234567890abcdef1234567890abcdefgh"',
    'echo "AWS key: AKIAIOSFODNN7EXAMPLE"',
    'echo "GitHub token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
    'echo "Email: user@example.com Phone: 555-123-4567"',
  ];

  const dlpResults = await runParallel(
    dlpCommands.map(cmd => () => executeInSandbox(sandbox, cmd))
  );

  const results: DemoResult[] = dlpCommands.map((cmd, i) => ({
    command: cmd, result: dlpResults[i]
  }));

  return Response.json({
    description: 'DLP redaction (note: only works on API proxy traffic, not command stdout)',
    note: 'For full DLP, route API calls through agentsh proxy',
    results
  }, { headers });
}

async function handleDemoNetwork(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  const networkCommands = [
    { cmd: 'curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>&1 || true', desc: 'Cloud metadata (BLOCKED)' },
    { cmd: 'curl -s --connect-timeout 2 http://10.0.0.1/ 2>&1 || true', desc: 'Private network (BLOCKED)' },
    { cmd: 'curl -s --connect-timeout 5 https://httpbin.org/get 2>&1 | head -5 || true', desc: 'External site (ALLOWED)' },
  ];

  const networkResults = await runParallel(
    networkCommands.map(({ cmd }) => () => executeInSandbox(sandbox, cmd, 15000))
  );

  const results: DemoResult[] = networkCommands.map(({ desc }, i) => ({
    command: desc, result: networkResults[i]
  }));

  return Response.json({
    description: 'Network policy blocks cloud metadata and private networks, allows external access',
    results
  }, { headers });
}

async function handleDemoCloudMetadata(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // All major cloud providers' metadata endpoints
  const metadataEndpoints = [
    { cmd: 'curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>&1', desc: 'AWS EC2 Metadata', provider: 'AWS' },
    { cmd: 'curl -s --connect-timeout 2 -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/ 2>&1', desc: 'GCP Metadata', provider: 'GCP' },
    { cmd: 'curl -s --connect-timeout 2 -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>&1', desc: 'Azure IMDS', provider: 'Azure' },
    { cmd: 'curl -s --connect-timeout 2 http://169.254.169.254/v1/ 2>&1', desc: 'DigitalOcean Metadata', provider: 'DigitalOcean' },
    { cmd: 'curl -s --connect-timeout 2 http://100.100.100.200/latest/meta-data/ 2>&1', desc: 'Alibaba Cloud Metadata', provider: 'Alibaba' },
    { cmd: 'curl -s --connect-timeout 2 http://169.254.169.254/opc/v1/instance/ 2>&1', desc: 'Oracle Cloud Metadata', provider: 'Oracle' },
  ];

  const metadataResults = await runParallel(
    metadataEndpoints.map(({ cmd }) => () => executeInSandbox(sandbox, cmd, 15000))
  );

  const results: DemoResult[] = metadataEndpoints.map(({ desc, provider }, i) => ({
    command: `${provider}: ${desc}`, result: metadataResults[i]
  }));

  return Response.json({
    title: 'Multi-Cloud Metadata Protection',
    description: 'agentsh blocks access to instance metadata endpoints across all major cloud providers. This prevents credential theft attacks where an agent is tricked into accessing cloud metadata to steal IAM credentials.',
    blocked: metadataEndpoints.length,
    results
  }, { headers });
}

async function handleDemoSSRF(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // SSRF attack vectors - focus on policy-blocked private networks
  const ssrfVectors = [
    // These are blocked by policy
    { cmd: 'curl -s --connect-timeout 2 http://169.254.169.254/ 2>&1', desc: 'AWS Metadata (169.254.169.254)', category: 'Cloud Metadata', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://10.0.0.1/ 2>&1', desc: '10.0.0.1 (Class A Private)', category: 'Private Network', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://10.255.255.1/ 2>&1', desc: '10.255.255.1 (Class A Private)', category: 'Private Network', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://172.16.0.1/ 2>&1', desc: '172.16.0.1 (Class B Private)', category: 'Private Network', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://172.31.255.1/ 2>&1', desc: '172.31.255.1 (Class B Private)', category: 'Private Network', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://192.168.1.1/ 2>&1', desc: '192.168.1.1 (Class C Private)', category: 'Private Network', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://192.168.255.1/ 2>&1', desc: '192.168.255.1 (Class C Private)', category: 'Private Network', policyBlocked: true },
    { cmd: 'curl -s --connect-timeout 2 http://169.254.1.1/ 2>&1', desc: '169.254.1.1 (Link-Local)', category: 'Link-Local', policyBlocked: true },
    // Contrast with allowed external
    { cmd: 'curl -s --connect-timeout 3 https://httpbin.org/ip 2>&1', desc: 'httpbin.org (External)', category: 'External', policyBlocked: false },
  ];

  const ssrfResults = await runParallel(
    ssrfVectors.map(({ cmd }) => () => executeInSandbox(sandbox, cmd, 15000))
  );

  const results: DemoResult[] = ssrfVectors.map(({ desc, category }, i) => ({
    command: `[${category}] ${desc}`, result: ssrfResults[i]
  }));

  return Response.json({
    title: 'SSRF Attack Prevention',
    description: 'Server-Side Request Forgery (SSRF) attacks trick applications into making requests to internal resources. agentsh blocks all RFC 1918 private networks, cloud metadata endpoints, and link-local addresses at the syscall level.',
    note: 'These blocks cannot be bypassed via DNS rebinding, URL encoding tricks, or prompt injection because enforcement happens at the network syscall level. The last entry shows that external HTTPS access is allowed.',
    results
  }, { headers });
}

async function handleDemoDevTools(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // Development tools that work in the sandbox
  const devToolCommands = [
    { cmd: 'python3 --version', desc: 'Python version' },
    { cmd: 'python3 -c "import json; print(json.dumps({\'hello\': \'world\'}))"', desc: 'Python JSON' },
    { cmd: 'node --version', desc: 'Node.js version' },
    { cmd: 'node -e "console.log(JSON.stringify({message: \'Hello from Node.js\'}))"', desc: 'Node.js inline (slow in Firecracker)' },
    { cmd: 'bun --version', desc: 'Bun version' },
    { cmd: 'pip3 list 2>/dev/null | head -10', desc: 'Python packages (first 10)' },
    { cmd: 'which git && git --version', desc: 'Git version' },
    { cmd: 'curl -s https://api.github.com/zen', desc: 'GitHub API (external HTTPS)' },
    { cmd: 'echo "SELECT 1+1 AS result;" | python3 -c "import sys; print(sys.stdin.read())"', desc: 'Pipe operations' },
    { cmd: 'ls -la /workspace', desc: 'Workspace directory' },
  ];

  const devToolResults = await runParallel(
    devToolCommands.map(({ cmd }) => () => executeInSandbox(sandbox, cmd))
  );

  const results: DemoResult[] = devToolCommands.map(({ desc }, i) => ({
    command: desc, result: devToolResults[i]
  }));

  return Response.json({
    title: 'Development Tools Demo',
    description: 'Normal development workflows work seamlessly within the agentsh sandbox. Python, Node.js, Bun, Git, and external HTTPS APIs are all available.',
    note: 'Security enforcement is transparent to legitimate operations while blocking dangerous network access and commands.',
    results
  }, { headers });
}

async function handleDemoFilesystem(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // Phase 1: Run all independent checks with limited concurrency
  const [detectResult, workspaceWrite, tmpWrite, etcPasswd, etcShadow,
         usrBinWrite, overwriteConfig, sudoersWrite] = await runParallel([
    () => executeRaw(sandbox, 'agentsh detect 2>&1 | grep -E "fuse|landlock|seccomp|Security Mode|Protection"'),
    () => executeInSandbox(sandbox, 'echo "hello from agent" > /workspace/test.txt && cat /workspace/test.txt'),
    () => executeInSandbox(sandbox, 'echo "temp data" > /tmp/test.txt && cat /tmp/test.txt'),
    () => executeInSandbox(sandbox, 'echo "hacked" >> /etc/passwd 2>&1; echo "exit=$?"'),
    () => executeInSandbox(sandbox, 'echo "hacked" >> /etc/shadow 2>&1; echo "exit=$?"'),
    () => executeInSandbox(sandbox, 'touch /usr/bin/malware 2>&1; echo "exit=$?"'),
    () => executeInSandbox(sandbox, 'echo "hacked" > /etc/agentsh/config.yaml 2>&1; echo "exit=$?"'),
    () => executeInSandbox(sandbox, 'echo "agent ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers 2>&1; echo "exit=$?"'),
  ]);

  // Phase 2: Delete workspace file (depends on workspace write above)
  const deleteFile = await executeInSandbox(sandbox, 'rm /workspace/test.txt 2>&1 && echo "deleted" && ls /workspace/test.txt 2>&1; echo "exit=$?"');

  const results: DemoResult[] = [
    { command: 'agentsh detect (security capabilities)', result: detectResult },
    { command: 'Write to /workspace/test.txt (ALLOWED)', result: workspaceWrite },
    { command: 'Write to /tmp/test.txt (ALLOWED)', result: tmpWrite },
    { command: 'Write to /etc/passwd (BLOCKED)', result: etcPasswd },
    { command: 'Write to /etc/shadow (BLOCKED)', result: etcShadow },
    { command: 'Create /usr/bin/malware (BLOCKED)', result: usrBinWrite },
    { command: 'Overwrite agentsh config (BLOCKED)', result: overwriteConfig },
    { command: 'Delete workspace file', result: deleteFile },
    { command: 'Write to /etc/sudoers (BLOCKED)', result: sudoersWrite },
  ];

  return Response.json({
    title: 'Filesystem Protection (Seccomp File Monitor + Landlock)',
    description: 'agentsh uses seccomp_unotify to intercept file syscalls (openat, unlinkat, mkdirat, etc.) and enforce file access policy. In Firecracker where FUSE and Landlock are unavailable, seccomp file monitoring provides kernel-level filesystem protection. Write access is limited to /workspace, /tmp, and /home/sandbox.',
    note: 'Seccomp file monitoring intercepts filesystem syscalls via seccomp_unotify, reads paths from process memory, and enforces file_rules policy. Landlock provides additional defense-in-depth where the kernel supports it (Linux 5.13+).',
    results
  }, { headers });
}

async function handleDemoCommands(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  const commands = [
    // Privilege escalation (2)
    { cmd: 'sudo id', desc: 'sudo id (privilege escalation)', category: 'Privilege Escalation' },
    { cmd: 'su - root', desc: 'su (switch user to root)', category: 'Privilege Escalation' },
    // SSH/remote access (2)
    { cmd: 'ssh user@example.com', desc: 'ssh (remote login)', category: 'SSH/Remote Access' },
    { cmd: 'scp file user@host:/tmp/', desc: 'scp (secure copy)', category: 'SSH/Remote Access' },
    // System admin (2)
    { cmd: 'shutdown -h now', desc: 'shutdown (halt system)', category: 'System Admin' },
    { cmd: 'mount /dev/sda1 /mnt', desc: 'mount (mount filesystem)', category: 'System Admin' },
    // Network tools (2)
    { cmd: 'nc -l 4444', desc: 'nc (netcat)', category: 'Network Tools' },
    { cmd: 'nmap localhost', desc: 'nmap (port scanner)', category: 'Network Tools' },
    // Process control (2)
    { cmd: 'killall agentsh', desc: 'killall agentsh (kill security)', category: 'Process Control' },
    { cmd: 'pkill -f agentsh', desc: 'pkill agentsh (pattern kill)', category: 'Process Control' },
  ];

  const commandResults = await runParallel(
    commands.map(({ cmd }) => () => executeInSandbox(sandbox, cmd, 15000))
  );

  const results: DemoResult[] = commands.map(({ desc, category }, i) => ({
    command: `[${category}] ${desc}`, result: commandResults[i]
  }));

  return Response.json({
    title: 'Command Blocking',
    description: 'agentsh blocks dangerous commands across multiple categories: privilege escalation, SSH/remote access, system administration, network tools, and process control. Commands are blocked at the policy level (command_rules) or at the kernel level (seccomp/Landlock) depending on the command type.',
    note: 'Top-level commands like sudo are blocked by command_rules. Sub-commands wrapped in bash -c are blocked at the kernel level via seccomp, which returns "Permission denied".',
    results
  }, { headers });
}

async function handleDemoPrivilegeEscalation(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // Run all command-level and file-level checks in parallel
  const [sudoId, sudoCat, suRoot, pkexec, readShadow, writeSudoers] = await runParallel([
    () => executeInSandbox(sandbox, 'sudo id', 15000),
    () => executeInSandbox(sandbox, 'sudo cat /etc/shadow', 15000),
    () => executeInSandbox(sandbox, 'su - root -c whoami', 15000),
    () => executeInSandbox(sandbox, 'pkexec cat /etc/shadow 2>&1', 15000),
    () => executeInSandbox(sandbox, 'cat /etc/shadow 2>&1', 15000),
    () => executeInSandbox(sandbox, 'echo "agent ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>&1', 15000),
  ]);

  const results: DemoResult[] = [
    { command: '[Command] sudo id (run as root)', result: sudoId },
    { command: '[Command] sudo cat /etc/shadow (read shadow file)', result: sudoCat },
    { command: '[Command] su - root (switch to root)', result: suRoot },
    { command: '[Command] pkexec (PolicyKit escalation)', result: pkexec },
    { command: '[File] Read /etc/shadow (password hashes)', result: readShadow },
    { command: '[File] Write /etc/sudoers (grant sudo)', result: writeSudoers },
  ];

  return Response.json({
    title: 'Privilege Escalation Prevention',
    description: 'agentsh prevents privilege escalation through two layers: command-level blocking (command_rules) stops tools like sudo, su, chroot, nsenter, and unshare. File-level blocking (seccomp file monitor + Landlock) prevents reading or writing sensitive files like /etc/shadow and /etc/sudoers.',
    note: 'Even if an attacker bypasses command blocking via bash -c wrapping, file-level enforcement still prevents access to sensitive files.',
    results
  }, { headers });
}

async function handleDemoStatus(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  const statusChecks = [
    { cmd: 'agentsh --version', desc: 'agentsh version' },
    { cmd: 'which agentsh', desc: 'agentsh binary location' },
    { cmd: 'agentsh detect 2>&1 | head -30', desc: 'agentsh detect (security capabilities)' },
    { cmd: 'ls -la /etc/agentsh/', desc: 'Config directory listing' },
    { cmd: 'ls -la /etc/agentsh/policies/', desc: 'Policies directory listing' },
    { cmd: 'head -5 /etc/agentsh/policies/default.yaml', desc: 'Policy file header' },
    { cmd: 'agentsh detect 2>&1 | grep -i seccomp || echo "seccomp status not available"', desc: 'Seccomp status' },
    { cmd: 'uname -r', desc: 'Kernel version' },
  ];

  const statusResults = await runParallel(
    statusChecks.map(({ cmd }) => () => executeRaw(sandbox, cmd))
  );

  const results: DemoResult[] = statusChecks.map(({ desc }, i) => ({
    command: desc, result: statusResults[i]
  }));

  return Response.json({
    title: 'agentsh Status',
    description: 'Current status and configuration of the agentsh security agent running in this Cloudflare sandbox.',
    note: 'These commands run outside of agentsh enforcement (raw execution) to show the security infrastructure itself.',
    results
  }, { headers });
}

async function handleStartAgentsh(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  // Start the agentsh server in background via raw exec (no agentsh exec needed)
  const startResult = await executeRaw(
    sandbox,
    'agentsh server --config /etc/agentsh/config.yaml &',
    10000,
  );

  // Poll the agentsh health endpoint until ready (up to 120s)
  const maxWait = 120;
  let ready = false;
  let elapsed = 0;
  for (let i = 0; i < maxWait; i++) {
    const health = await executeRaw(
      sandbox,
      'curl -sf http://127.0.0.1:18080/health 2>/dev/null && echo "OK" || echo "NOT_READY"',
      5000,
    );
    if (health.stdout.includes('OK')) {
      ready = true;
      elapsed = i + 1;
      break;
    }
    // Wait 1 second between checks
    await new Promise(r => setTimeout(r, 1000));
  }

  return Response.json({
    started: true,
    ready,
    elapsedSeconds: elapsed,
    startOutput: startResult.stdout,
  }, { headers });
}

async function handleTerminal(
  sandbox: SandboxInstance,
  headers: Record<string, string>
): Promise<Response> {
  return Response.json({
    message: 'Terminal access requires preview URL setup',
    note: 'Preview URLs need a custom domain with wildcard DNS configured.',
    instruction: 'See https://developers.cloudflare.com/sandbox/guides/expose-services/',
    port: 7681,
  }, { headers });
}

// Run multiple commands with limited concurrency to avoid overwhelming the
// 0.25 vCPU Firecracker VM. Reduces handler time from N*T to ceil(N/C)*T.
async function runParallel<T>(
  tasks: Array<() => Promise<T>>,
  concurrency: number = 3
): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  for (let i = 0; i < tasks.length; i += concurrency) {
    const batch = tasks.slice(i, i + concurrency);
    const batchResults = await Promise.all(batch.map(fn => fn()));
    for (let j = 0; j < batchResults.length; j++) {
      results[i + j] = batchResults[j];
    }
  }
  return results;
}

async function executeInSandbox(
  sandbox: SandboxInstance,
  command: string,
  timeout: number = 60000,
  useAgentsh: boolean = true
): Promise<ExecuteResponse> {
  const maxRetries = 1;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const actualCommand = useAgentsh
        ? `agentsh exec --root=/workspace demo -- /bin/bash -c ${JSON.stringify(command)}`
        : command;

      const result = await sandbox.exec(actualCommand, { timeout });

      const stdout = result.stdout || '';
      const stderr = result.stderr || '';
      const combinedOutput = stdout + stderr;

      const blocked = combinedOutput.includes('command denied by policy') ||
                     combinedOutput.includes('blocked by policy') ||
                     combinedOutput.includes('BLOCKED:') ||
                     combinedOutput.includes('Permission denied') ||
                     combinedOutput.includes('Operation not permitted');

      const cleanedStdout = stdout
        .replace(/agentsh: auto-starting server[^\n]*\n?/g, '')
        .replace(/\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2} INFO[^\n]*\n?/g, '')
        .trim();

      return {
        success: result.success && !blocked,
        stdout: cleanedStdout,
        stderr: stderr,
        exitCode: result.exitCode,
        blocked,
        message: blocked ? extractBlockMessage(combinedOutput) : undefined,
      };
    } catch (error) {
      const errStr = String(error);
      const isRetryable = errStr.includes('Network connection lost') ||
                         errStr.includes('Container service disconnected') ||
                         errStr.includes('EOF');
      if (isRetryable && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 2000));
        continue;
      }
      return {
        success: false,
        stdout: '',
        stderr: errStr,
        exitCode: -1,
        blocked: false,
        message: 'Execution error: ' + errStr,
      };
    }
  }
  // Should not reach here, but TypeScript needs this
  return { success: false, stdout: '', stderr: 'Max retries exceeded', exitCode: -1, blocked: false };
}

function executeRaw(
  sandbox: SandboxInstance,
  command: string,
  timeout: number = 60000
): Promise<ExecuteResponse> {
  return executeInSandbox(sandbox, command, timeout, false);
}

function extractBlockMessage(output: string): string {
  const policyMatch = output.match(/command denied by policy[^)]*\(rule=([^)]+)\)/);
  if (policyMatch) {
    return `Blocked by policy: ${policyMatch[1]}`;
  }
  const blockedMatch = output.match(/blocked by policy[^)]*\(rule=([^)]+)\)/);
  if (blockedMatch) {
    return `Blocked by policy: ${blockedMatch[1]}`;
  }
  const blockMatch = output.match(/BLOCKED:\s*(.+)/);
  if (blockMatch) {
    return blockMatch[1];
  }
  if (output.includes('Permission denied')) {
    return 'Permission denied (kernel-level enforcement)';
  }
  if (output.includes('Operation not permitted')) {
    return 'Operation not permitted (kernel-level enforcement)';
  }
  return 'Command blocked by policy';
}
