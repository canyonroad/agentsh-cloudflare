import { spawn, execSync, type ChildProcess } from "node:child_process";

const TEST_PORT = process.env.TEST_PORT || "8686";
const BASE_URL = process.env.TEST_BASE_URL || `http://localhost:${TEST_PORT}`;
const STARTUP_TIMEOUT = 180_000; // 3 minutes for container build + start
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

export async function setup(): Promise<{ baseUrl: string }> {
	// If TEST_BASE_URL is set, assume the server is already running externally
	if (process.env.TEST_BASE_URL) {
		console.log(
			`[test] Using external server at ${process.env.TEST_BASE_URL}`,
		);
		await waitForReady();
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
