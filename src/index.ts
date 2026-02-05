/**
 * Cloudflare Worker with agentsh-protected Sandbox
 *
 * Demonstrates secure AI agent code execution with:
 * - Command blocking (sudo, ssh, nc, etc.)
 * - Network control (blocks metadata services, private networks)
 * - Rate limiting and Turnstile protection
 */

import { getSandbox, type Sandbox } from "@cloudflare/sandbox";

// Re-export Sandbox class for Durable Objects
export { Sandbox } from "@cloudflare/sandbox";

type Env = {
  SANDBOX: DurableObjectNamespace<Sandbox>;
  RATE_LIMIT: KVNamespace;
  ENVIRONMENT: string;
  TURNSTILE_SITE_KEY: string;
  TURNSTILE_SECRET_KEY: string;
};

// Type for the stub returned by getSandbox
type SandboxStub = DurableObjectStub<Sandbox>;

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
      background: var(--evergreen);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: white;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      font-size: 20px;
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
        <div class="logo-mark">ag</div>
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
        <button class="btn btn-secondary" onclick="runDemo('network')">Demo: Network Blocking</button>
        <button class="btn btn-secondary" onclick="runDemo('allowed')">Demo: Allowed Commands</button>
        <button class="btn btn-secondary" onclick="runDemo('blocked')">Demo: Policy File</button>
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
        <span class="method">GET</span> <span class="path">/demo/network</span>
      </div>
      <p>Demo network blocking (metadata services, private IPs, external access)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/allowed</span>
      </div>
      <p>Demo allowed commands and agentsh security capabilities</p>
    </div>
  </div>

  <footer class="footer">
    <div class="footer-links">
      <a href="https://www.agentsh.org?${utmAgentsh}">agentsh.org</a>
      <a href="https://www.agentsh.org/docs?${utmAgentsh}">Documentation</a>
      <a href="https://github.com/canyonroad/agentsh?${utmAgentsh}">GitHub</a>
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
      let status = result.blocked ? '<span class="blocked">BLOCKED</span>' : '<span class="allowed">OK</span>';
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

    // Check rate limit for all non-health endpoints
    if (path !== '/health') {
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
      const sandbox = getSandbox(env.SANDBOX, 'demo-sandbox');

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
  sandbox: SandboxStub,
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
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  // Show the policy file first (using raw execution)
  const policyResult = await executeRaw(sandbox, 'cat /etc/agentsh/policies/default.yaml | head -50');

  // These commands ARE blocked by the agentsh policy
  const blockedCommands = [
    { cmd: 'nc -h', reason: 'network tool blocked' },
    { cmd: 'nmap --version', reason: 'network scanner blocked' },
    { cmd: 'curl http://169.254.169.254/latest/meta-data/', reason: 'cloud metadata blocked' },
  ];

  const results: DemoResult[] = [
    { command: 'Policy file (head -50)', result: policyResult },
  ];

  for (const { cmd, reason } of blockedCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({
      command: `${cmd} (${reason})`,
      result
    });
  }

  return Response.json({
    description: 'agentsh policy enforcement is ACTIVE. These commands are blocked by policy.',
    note: 'Commands are executed through agentsh exec which enforces the security policy.',
    policyPath: '/etc/agentsh/policies/default.yaml',
    results
  }, { headers });
}

async function handleDemoAllowed(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  // Show agentsh installation (using raw execution for system checks)
  const agentshVersion = await executeRaw(sandbox, 'agentsh --version');
  const agentshLocation = await executeRaw(sandbox, 'which agentsh');
  const configCheck = await executeRaw(sandbox, 'ls -la /etc/agentsh/');
  const detectResult = await executeRaw(sandbox, 'agentsh detect 2>&1 | head -20');

  // These are safe commands that are allowed by policy
  const allowedCommands = [
    'whoami',
    'pwd',
    'ls -la /workspace',
    'echo "Hello from agentsh sandbox!"',
  ];

  const results: DemoResult[] = [
    { command: 'agentsh --version', result: agentshVersion },
    { command: 'which agentsh', result: agentshLocation },
    { command: 'ls -la /etc/agentsh/', result: configCheck },
    { command: 'agentsh detect (security capabilities)', result: detectResult },
  ];

  for (const cmd of allowedCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'agentsh is installed with full security capabilities. These commands are allowed by policy.',
    note: 'All user commands go through agentsh exec for policy enforcement.',
    results
  }, { headers });
}

async function handleDemoDLP(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  // These contain fake secrets that should be redacted by DLP
  const dlpCommands = [
    'echo "OpenAI key: sk-1234567890abcdef1234567890abcdef1234567890abcdefgh"',
    'echo "AWS key: AKIAIOSFODNN7EXAMPLE"',
    'echo "GitHub token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
    'echo "Email: user@example.com Phone: 555-123-4567"',
  ];

  const results: DemoResult[] = [];

  for (const cmd of dlpCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'DLP redaction (note: only works on API proxy traffic, not command stdout)',
    note: 'For full DLP, route API calls through agentsh proxy',
    results
  }, { headers });
}

async function handleDemoNetwork(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  const networkCommands = [
    { cmd: 'curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>&1 || true', desc: 'Cloud metadata (BLOCKED)' },
    { cmd: 'curl -s --connect-timeout 2 http://10.0.0.1/ 2>&1 || true', desc: 'Private network (BLOCKED)' },
    { cmd: 'curl -s --connect-timeout 5 https://httpbin.org/get 2>&1 | head -5 || true', desc: 'External site (ALLOWED)' },
  ];

  const results: DemoResult[] = [];

  for (const { cmd, desc } of networkCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: desc, result });
  }

  return Response.json({
    description: 'Network policy blocks cloud metadata and private networks, allows external access',
    results
  }, { headers });
}

async function handleTerminal(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  return Response.json({
    message: 'Terminal access requires preview URL setup',
    note: 'Preview URLs need a custom domain with wildcard DNS configured.',
    instruction: 'See https://developers.cloudflare.com/sandbox/guides/expose-services/',
    port: 7681,
  }, { headers });
}

async function executeInSandbox(
  sandbox: DurableObjectStub<Sandbox>,
  command: string,
  timeout: number = 30000,
  useAgentsh: boolean = true
): Promise<ExecuteResponse> {
  try {
    const sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;

    const actualCommand = useAgentsh
      ? `agentsh exec --root=/workspace demo -- /bin/bash -c ${JSON.stringify(command)}`
      : command;

    const response = await sandbox.fetch(new Request('http://sandbox/api/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command: actualCommand,
        timeout,
        sessionId,
      }),
    }));

    if (!response.ok) {
      const errorText = await response.text();
      return {
        success: false,
        stdout: '',
        stderr: `Sandbox API error: ${response.status} - ${errorText}`,
        exitCode: -1,
        blocked: false,
        message: `Sandbox error: ${response.status}`,
      };
    }

    const result = await response.json() as {
      success: boolean;
      stdout: string;
      stderr: string;
      exitCode: number;
    };

    const stdout = result.stdout || '';
    const stderr = result.stderr || '';
    const combinedOutput = stdout + stderr;

    const blocked = combinedOutput.includes('command denied by policy') ||
                   combinedOutput.includes('blocked by policy') ||
                   combinedOutput.includes('BLOCKED:');

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
    return {
      success: false,
      stdout: '',
      stderr: String(error),
      exitCode: -1,
      blocked: false,
      message: 'Execution error: ' + String(error),
    };
  }
}

function executeRaw(
  sandbox: DurableObjectStub<Sandbox>,
  command: string,
  timeout: number = 30000
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
  return 'Command blocked by policy';
}
