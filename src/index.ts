/**
 * Cloudflare Worker with agentsh-protected Sandbox
 *
 * Demonstrates secure AI agent code execution with:
 * - Command blocking (sudo, ssh, nc, etc.)
 * - Network control (blocks metadata services, private networks)
 * - DLP (redacts API keys and sensitive data)
 * - Web terminal access via ttyd
 */

import { Sandbox, getSandbox } from '@cloudflare/sandbox';

export interface Env {
  SANDBOX: DurableObjectNamespace;
  ENVIRONMENT: string;
}

interface ExecuteRequest {
  command: string;
  timeout?: number;
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

// HTML template for the demo page
const HTML_TEMPLATE = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>agentsh on Cloudflare - Demo</title>
  <style>
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
      background: #0f0f0f;
      color: #e0e0e0;
      margin: 0;
      padding: 20px;
      line-height: 1.6;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { color: #f97316; margin-bottom: 10px; }
    h2 { color: #22c55e; margin-top: 30px; }
    .subtitle { color: #888; margin-bottom: 30px; }
    .card {
      background: #1a1a1a;
      border: 1px solid #333;
      border-radius: 8px;
      padding: 20px;
      margin: 15px 0;
    }
    .endpoint {
      background: #252525;
      padding: 10px 15px;
      border-radius: 4px;
      margin: 10px 0;
      font-family: monospace;
    }
    .method { color: #22c55e; font-weight: bold; }
    .path { color: #60a5fa; }
    pre {
      background: #000;
      padding: 15px;
      border-radius: 4px;
      overflow-x: auto;
      border: 1px solid #333;
    }
    code { color: #f97316; }
    .blocked { color: #ef4444; }
    .allowed { color: #22c55e; }
    .btn {
      background: #f97316;
      color: #000;
      border: none;
      padding: 10px 20px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: bold;
      margin: 5px;
    }
    .btn:hover { background: #fb923c; }
    .btn-secondary { background: #333; color: #fff; }
    .btn-secondary:hover { background: #444; }
    #output {
      background: #000;
      padding: 15px;
      border-radius: 4px;
      min-height: 200px;
      font-family: monospace;
      white-space: pre-wrap;
      border: 1px solid #333;
    }
    .feature-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 15px;
    }
    .feature {
      background: #1a1a1a;
      border: 1px solid #333;
      border-radius: 8px;
      padding: 15px;
    }
    .feature h3 { color: #f97316; margin-top: 0; }
    a { color: #60a5fa; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ agentsh on Cloudflare</h1>
    <p class="subtitle">Secure AI agent code execution with policy enforcement</p>

    <div class="feature-grid">
      <div class="feature">
        <h3>🚫 Command Blocking</h3>
        <p>Blocks dangerous commands like <code>sudo</code>, <code>ssh</code>, <code>nc</code>, <code>kill</code></p>
      </div>
      <div class="feature">
        <h3>🌐 Network Control</h3>
        <p>Blocks cloud metadata services, private networks, and malicious domains</p>
      </div>
      <div class="feature">
        <h3>🔒 DLP Protection</h3>
        <p>Redacts API keys, tokens, and sensitive data before LLM exposure</p>
      </div>
      <div class="feature">
        <h3>📁 File Protection</h3>
        <p>Soft-deletes for recovery, blocks access to system files</p>
      </div>
    </div>

    <h2>API Endpoints</h2>

    <div class="card">
      <div class="endpoint">
        <span class="method">POST</span> <span class="path">/execute</span>
      </div>
      <p>Execute a command in the sandbox. Body: <code>{"command": "your command"}</code></p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/blocked</span>
      </div>
      <p>Demo: Try blocked commands (sudo, ssh, nc)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/allowed</span>
      </div>
      <p>Demo: Try allowed commands (ls, python, echo)</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/demo/dlp</span>
      </div>
      <p>Demo: Show DLP redaction of API keys</p>

      <div class="endpoint">
        <span class="method">GET</span> <span class="path">/terminal</span>
      </div>
      <p>Get URL to interactive web terminal</p>
    </div>

    <h2>Try It</h2>
    <div class="card">
      <input type="text" id="command" placeholder="Enter command (e.g., ls -la)"
             style="width: 100%; padding: 10px; background: #252525; border: 1px solid #333; color: #fff; border-radius: 4px; margin-bottom: 10px;">
      <div>
        <button class="btn" onclick="executeCommand()">Execute</button>
        <button class="btn btn-secondary" onclick="runDemo('blocked')">Demo: Blocked</button>
        <button class="btn btn-secondary" onclick="runDemo('allowed')">Demo: Allowed</button>
        <button class="btn btn-secondary" onclick="runDemo('dlp')">Demo: DLP</button>
        <button class="btn btn-secondary" onclick="openTerminal()">Open Terminal</button>
      </div>
      <h3>Output:</h3>
      <div id="output">Ready...</div>
    </div>
  </div>

  <script>
    async function executeCommand() {
      const command = document.getElementById('command').value;
      const output = document.getElementById('output');
      output.textContent = 'Executing...';

      try {
        const res = await fetch('/execute', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ command })
        });
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
        const data = await res.json();
        output.innerHTML = data.results.map(r => formatResult(r.command, r.result)).join('\\n---\\n');
      } catch (e) {
        output.textContent = 'Error: ' + e.message;
      }
    }

    async function openTerminal() {
      try {
        const res = await fetch('/terminal');
        const data = await res.json();
        if (data.url) {
          window.open(data.url, '_blank');
        } else {
          document.getElementById('output').textContent = 'Terminal URL: ' + JSON.stringify(data);
        }
      } catch (e) {
        document.getElementById('output').textContent = 'Error: ' + e.message;
      }
    }

    function formatResult(command, result) {
      let status = result.blocked ? '<span class="blocked">BLOCKED</span>' : '<span class="allowed">OK</span>';
      let output = '$ ' + command + ' [' + status + ']\\n';
      if (result.stdout) output += result.stdout;
      if (result.stderr) output += '<span class="blocked">' + result.stderr + '</span>';
      if (result.message) output += '<span class="blocked">' + result.message + '</span>';
      return output;
    }

    document.getElementById('command').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') executeCommand();
    });
  </script>
</body>
</html>`;

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS headers
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers });
    }

    try {
      // Route handling
      if (path === '/' || path === '') {
        return new Response(HTML_TEMPLATE, {
          headers: { ...headers, 'Content-Type': 'text/html' },
        });
      }

      if (path === '/execute' && request.method === 'POST') {
        return await handleExecute(request, env, headers);
      }

      if (path === '/demo/blocked') {
        return await handleDemoBlocked(env, headers);
      }

      if (path === '/demo/allowed') {
        return await handleDemoAllowed(env, headers);
      }

      if (path === '/demo/dlp') {
        return await handleDemoDLP(env, headers);
      }

      if (path === '/terminal') {
        return await handleTerminal(env, headers);
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
  headers: Record<string, string>
): Promise<Response> {
  const body = await request.json() as ExecuteRequest;

  if (!body.command) {
    return Response.json({ error: 'Missing command' }, { status: 400, headers });
  }

  const sandbox = await getSandbox(env.SANDBOX, 'demo-sandbox');
  const result = await executeInSandbox(sandbox, body.command, body.timeout);

  return Response.json(result, { headers });
}

async function handleDemoBlocked(
  env: Env,
  headers: Record<string, string>
): Promise<Response> {
  const blockedCommands = [
    'sudo whoami',
    'ssh localhost',
    'nc -l 8080',
    'kill -9 1',
    'systemctl status',
    'curl http://169.254.169.254/latest/meta-data/',  // AWS metadata
  ];

  const sandbox = await getSandbox(env.SANDBOX, 'demo-sandbox');
  const results: DemoResult[] = [];

  for (const cmd of blockedCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'These commands are blocked by agentsh policy',
    results
  }, { headers });
}

async function handleDemoAllowed(
  env: Env,
  headers: Record<string, string>
): Promise<Response> {
  const allowedCommands = [
    'whoami',
    'pwd',
    'ls -la',
    'python3 --version',
    'node --version',
    'echo "Hello from agentsh sandbox!"',
    'date',
    'cat /etc/os-release | head -5',
  ];

  const sandbox = await getSandbox(env.SANDBOX, 'demo-sandbox');
  const results: DemoResult[] = [];

  for (const cmd of allowedCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'These commands are allowed by agentsh policy',
    results
  }, { headers });
}

async function handleDemoDLP(
  env: Env,
  headers: Record<string, string>
): Promise<Response> {
  // These contain fake secrets that should be redacted by DLP
  const dlpCommands = [
    'echo "OpenAI key: sk-1234567890abcdef1234567890abcdef1234567890abcdefgh"',
    'echo "AWS key: AKIAIOSFODNN7EXAMPLE"',
    'echo "GitHub token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"',
    'echo "My email is user@example.com and phone is 555-123-4567"',
    'echo "Credit card: 4111-1111-1111-1111"',
  ];

  const sandbox = await getSandbox(env.SANDBOX, 'demo-sandbox');
  const results: DemoResult[] = [];

  for (const cmd of dlpCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'DLP redacts sensitive data (API keys, emails, cards) from output',
    note: 'In a real scenario, this prevents accidental exposure of secrets to LLMs',
    results
  }, { headers });
}

async function handleTerminal(
  env: Env,
  headers: Record<string, string>
): Promise<Response> {
  const sandbox = await getSandbox(env.SANDBOX, 'demo-sandbox');

  // Get the preview URL for the ttyd terminal (port 7681)
  const previewUrl = await sandbox.getPreviewUrl(7681);

  return Response.json({
    url: previewUrl,
    description: 'Web terminal with agentsh protection. All commands go through policy enforcement.',
    note: 'Try running blocked commands like "sudo su" or "nc -l 8080" to see them blocked in real-time.',
  }, { headers });
}

async function executeInSandbox(
  sandbox: Sandbox,
  command: string,
  timeout: number = 30000
): Promise<ExecuteResponse> {
  try {
    const result = await sandbox.exec(command, { timeout });

    // Check if the command was blocked by agentsh
    const blocked = result.stderr?.includes('BLOCKED:') ||
                   result.exitCode !== 0 && result.stderr?.includes('not allowed');

    return {
      success: result.exitCode === 0 && !blocked,
      stdout: result.stdout || '',
      stderr: result.stderr || '',
      exitCode: result.exitCode,
      blocked,
      message: blocked ? extractBlockMessage(result.stderr) : undefined,
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

function extractBlockMessage(stderr: string): string {
  const match = stderr.match(/BLOCKED:\s*(.+)/);
  return match ? match[1] : 'Command blocked by policy';
}

// Durable Object for sandbox state management
export class SandboxDO {
  state: DurableObjectState;

  constructor(state: DurableObjectState) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    return new Response('Sandbox DO');
  }
}
