/**
 * Cloudflare Worker with agentsh-protected Sandbox
 *
 * Demonstrates secure AI agent code execution with:
 * - Command blocking (sudo, ssh, nc, etc.)
 * - Network control (blocks metadata services, private networks)
 * - DLP (redacts API keys and sensitive data)
 * - Web terminal access via ttyd
 */

import { getSandbox, type Sandbox } from "@cloudflare/sandbox";

// Re-export Sandbox class for Durable Objects
export { Sandbox } from "@cloudflare/sandbox";

type Env = {
  SANDBOX: DurableObjectNamespace<Sandbox>;
  ENVIRONMENT: string;
};

// Type for the stub returned by getSandbox
type SandboxStub = DurableObjectStub<Sandbox>;

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
    <h1>agentsh on Cloudflare</h1>
    <p class="subtitle">Secure AI agent code execution with policy enforcement</p>

    <div class="feature-grid">
      <div class="feature">
        <h3>Command Blocking</h3>
        <p>Blocks dangerous commands like <code>sudo</code>, <code>ssh</code>, <code>nc</code>, <code>kill</code></p>
      </div>
      <div class="feature">
        <h3>Network Control</h3>
        <p>Blocks cloud metadata services, private networks, and malicious domains</p>
      </div>
      <div class="feature">
        <h3>DLP Protection</h3>
        <p>Redacts API keys, tokens, and sensitive data before LLM exposure</p>
      </div>
      <div class="feature">
        <h3>File Protection</h3>
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
        <span class="method">GET</span> <span class="path">/demo/network</span>
      </div>
      <p>Demo: Show network blocking (metadata, private networks)</p>

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
        <button class="btn btn-secondary" onclick="runDemo('network')">Demo: Network</button>
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
          document.getElementById('output').textContent = 'Terminal: ' + JSON.stringify(data, null, 2);
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
      // Get sandbox instance (shared across requests for demo)
      const sandbox = getSandbox(env.SANDBOX, 'demo-sandbox');

      // Route handling
      if (path === '/' || path === '') {
        return new Response(HTML_TEMPLATE, {
          headers: { ...headers, 'Content-Type': 'text/html' },
        });
      }

      if (path === '/execute' && request.method === 'POST') {
        return await handleExecute(request, sandbox, headers);
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
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  const body = await request.json() as ExecuteRequest;

  if (!body.command) {
    return Response.json({ error: 'Missing command' }, { status: 400, headers });
  }

  const result = await executeInSandbox(sandbox, body.command, body.timeout);

  return Response.json(result, { headers });
}

async function handleDemoBlocked(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  // Note: agentsh policy enforcement requires the agentsh server to be running.
  // In this demo, we show what commands WOULD be blocked by the policy.
  // The policy is configured but the server isn't running in this container setup.

  // Show the policy file first
  const policyResult = await executeInSandbox(sandbox, 'cat /etc/agentsh/policies/default.yaml | head -50');

  // These commands would be blocked if the agentsh server were running
  const blockedCommands = [
    { cmd: 'which sudo', reason: 'sudo is blocked by policy' },
    { cmd: 'which ssh', reason: 'ssh is blocked by policy' },
    { cmd: 'which nc', reason: 'nc (netcat) is blocked by policy' },
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
    description: 'agentsh policy is configured but server not running. These commands WOULD be blocked with full integration.',
    note: 'Full integration requires running agentsh server before the sandbox server.',
    policyPath: '/etc/agentsh/policies/default.yaml',
    results
  }, { headers });
}

async function handleDemoAllowed(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  // Show agentsh installation
  const agentshVersion = await executeInSandbox(sandbox, 'agentsh --version');
  const agentshLocation = await executeInSandbox(sandbox, 'which agentsh');
  const configCheck = await executeInSandbox(sandbox, 'ls -la /etc/agentsh/');

  // These are safe commands that would be allowed
  const allowedCommands = [
    'whoami',
    'pwd',
    'ls -la /workspace',
    'python3 --version',
    'node --version',
    'echo "Hello from agentsh-enabled sandbox!"',
    'date',
  ];

  const results: DemoResult[] = [
    { command: 'agentsh --version', result: agentshVersion },
    { command: 'which agentsh', result: agentshLocation },
    { command: 'ls -la /etc/agentsh/', result: configCheck },
  ];

  for (const cmd of allowedCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'agentsh is installed and configured. These commands would be allowed by policy.',
    note: 'Policy file at /etc/agentsh/policies/default.yaml',
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
    description: 'DLP redacts sensitive data (API keys, emails, cards) from output',
    note: 'In a real scenario, this prevents accidental exposure of secrets to LLMs',
    results
  }, { headers });
}

async function handleDemoNetwork(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  const networkCommands = [
    'curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/ 2>&1 || true',
    'curl -s --connect-timeout 2 http://10.0.0.1/ 2>&1 || true',
    'curl -s --connect-timeout 2 https://httpbin.org/get 2>&1 | head -5 || true',
  ];

  const results: DemoResult[] = [];

  for (const cmd of networkCommands) {
    const result = await executeInSandbox(sandbox, cmd);
    results.push({ command: cmd, result });
  }

  return Response.json({
    description: 'Network policy blocks cloud metadata and private networks',
    results
  }, { headers });
}

async function handleTerminal(
  sandbox: SandboxStub,
  headers: Record<string, string>
): Promise<Response> {
  // Note: Preview URLs require custom domain setup with wildcard DNS
  // For now, return instructions on how to access the terminal
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
  timeout: number = 30000
): Promise<ExecuteResponse> {
  try {
    // Generate a unique session ID for each request to avoid stale session issues
    const sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2)}`;

    // Use fetch-based API to call the sandbox's internal execute endpoint
    // The containerFetch will automatically start the container if needed
    const response = await sandbox.fetch(new Request('http://sandbox/api/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        command,
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

    // Check if the command was blocked by agentsh
    const blocked = result.stderr?.includes('blocked by policy') ||
                   result.stderr?.includes('BLOCKED:') ||
                   (result.exitCode !== 0 && result.stderr?.includes('not allowed'));

    return {
      success: result.success && !blocked,
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
  const policyMatch = stderr.match(/blocked by policy[^)]*\(rule=([^)]+)\)/);
  if (policyMatch) {
    return `Blocked by policy: ${policyMatch[1]}`;
  }
  const blockMatch = stderr.match(/BLOCKED:\s*(.+)/);
  if (blockMatch) {
    return blockMatch[1];
  }
  return 'Command blocked by policy';
}
