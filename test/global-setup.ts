import { spawn, execSync, type ChildProcess } from "node:child_process";

const TEST_PORT = process.env.TEST_PORT || "8686";
const BASE_URL = process.env.TEST_BASE_URL || `http://localhost:${TEST_PORT}`;
const STARTUP_TIMEOUT = 180_000; // 3 minutes for container build + start
const SANDBOX_WARMUP_TIMEOUT = 600_000; // 10 minutes for sandbox + agentsh server startup
const HEALTH_POLL_INTERVAL = 2_000;

let wranglerProcess: ChildProcess | null = null;

async function waitForReady(): Promise<void> {
	const deadline = Date.now() + STARTUP_TIMEOUT;
	while (Date.now() < deadline) {
		try {
			const res = await fetch(`${BASE_URL}/health`);
			if (res.ok) {
				console.log(`[test] wrangler dev is ready at ${BASE_URL}`);
				return;
			}
		} catch {
			// Not ready yet
		}
		await new Promise((r) => setTimeout(r, HEALTH_POLL_INTERVAL));
	}
	throw new Error(
		`wrangler dev did not become ready within ${STARTUP_TIMEOUT / 1000}s`,
	);
}

async function warmupSandbox(): Promise<void> {
	console.log("[test] Warming up sandbox (this may take 2-3 minutes on cold start)...");
	const deadline = Date.now() + SANDBOX_WARMUP_TIMEOUT;

	// Step 1: Wait for raw sandbox exec (container is up, no agentsh needed)
	while (Date.now() < deadline) {
		try {
			const res = await fetch(`${BASE_URL}/demo/status`);
			if (res.ok) {
				const data = (await res.json()) as {
					results: Array<{ result: { success: boolean } }>;
				};
				if (data.results?.some((r) => r.result.success)) {
					console.log("[test] Sandbox container is up");
					break;
				}
			}
		} catch {
			// Sandbox not ready yet
		}
		await new Promise((r) => setTimeout(r, HEALTH_POLL_INTERVAL));
	}

	// Step 2: Wait for agentsh exec path (agentsh server must be running)
	console.log("[test] Warming agentsh exec path...");
	while (Date.now() < deadline) {
		try {
			const res = await fetch(`${BASE_URL}/demo/blocked`);
			if (res.ok) {
				const data = (await res.json()) as {
					results: Array<{ result: { success: boolean; blocked: boolean } }>;
				};
				// Verify at least one result shows actual policy enforcement (not just a 200)
				if (data.results?.some((r) => r.result.blocked || r.result.success)) {
					console.log("[test] Sandbox is warm and ready");
					return;
				}
			}
		} catch {
			// Not ready yet
		}
		await new Promise((r) => setTimeout(r, HEALTH_POLL_INTERVAL));
	}
	console.warn("[test] Sandbox warmup timed out — tests may be flaky");
}

export async function setup(): Promise<{ baseUrl: string }> {
	// If TEST_BASE_URL is set, assume the server is already running externally
	if (process.env.TEST_BASE_URL) {
		console.log(
			`[test] Using external server at ${process.env.TEST_BASE_URL}`,
		);
		await waitForReady();
		await warmupSandbox();
		return { baseUrl: process.env.TEST_BASE_URL };
	}

	// Kill any leftover process on the test port
	try {
		execSync(`lsof -ti:${TEST_PORT} | xargs -r kill -9 2>/dev/null`, {
			stdio: "ignore",
		});
	} catch {
		// No process to kill
	}

	console.log(`[test] Starting wrangler dev on port ${TEST_PORT}...`);
	wranglerProcess = spawn(
		"npx",
		["wrangler", "dev", "--port", TEST_PORT],
		{
			stdio: ["ignore", "pipe", "pipe"],
			cwd: process.cwd(),
		},
	);

	// Log wrangler output for debugging
	wranglerProcess.stdout?.on("data", (data: Buffer) => {
		const line = data.toString().trim();
		if (line) console.log(`[wrangler] ${line}`);
	});
	wranglerProcess.stderr?.on("data", (data: Buffer) => {
		const line = data.toString().trim();
		if (line) console.log(`[wrangler:err] ${line}`);
	});

	wranglerProcess.on("exit", (code) => {
		if (code !== null && code !== 0) {
			console.error(`[test] wrangler dev exited with code ${code}`);
		}
	});

	await waitForReady();
	await warmupSandbox();
	return { baseUrl: BASE_URL };
}

export async function teardown(): Promise<void> {
	if (wranglerProcess) {
		console.log("[test] Stopping wrangler dev...");
		wranglerProcess.kill("SIGTERM");
		// Give it a moment to clean up
		await new Promise((r) => setTimeout(r, 2_000));
		if (!wranglerProcess.killed) {
			wranglerProcess.kill("SIGKILL");
		}
		wranglerProcess = null;
	}
}
