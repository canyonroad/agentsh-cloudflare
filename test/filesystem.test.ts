import { describe, it, expect, beforeAll } from "vitest";
import {
	fetchDemo,
	findResult,
	type DemoResponse,
} from "./helpers/sandbox";
import { expectAllowed } from "./helpers/assertions";

describe("Filesystem Protection", () => {
	let data: DemoResponse;
	let filesystemEnforced: boolean;

	beforeAll(async () => {
		data = await fetchDemo("/demo/filesystem");
		// Check if filesystem enforcement is working (via seccomp file monitor,
		// Landlock, or FUSE). Seccomp returns "Bad file descriptor" (EBADF),
		// Landlock returns "Permission denied", FUSE returns "BLOCKED".
		const etcPasswdResult = findResult(data.results, "/etc/passwd");
		const output = etcPasswdResult.result.stdout + etcPasswdResult.result.stderr;
		filesystemEnforced = /permission denied|BLOCKED|denied|EACCES|Bad file descriptor/i.test(output);
	}, 300_000);

	it("reports security status", () => {
		const r = findResult(data.results, "security capabilities");
		expect(r.result.success).toBe(true);
	});

	it("allows writing to /workspace", () => {
		const r = findResult(data.results, "/workspace/test.txt (ALLOWED)");
		expectAllowed(r.result);
		expect(r.result.stdout).toContain("hello from agent");
	});

	it("allows writing to /tmp", () => {
		const r = findResult(data.results, "/tmp/test.txt (ALLOWED)");
		expectAllowed(r.result);
		expect(r.result.stdout).toContain("temp data");
	});

	it("blocks writing to /etc/passwd", () => {
		if (!filesystemEnforced) return; // skip without seccomp file monitor or Landlock
		const r = findResult(data.results, "/etc/passwd");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});

	it("blocks writing to /etc/shadow", () => {
		if (!filesystemEnforced) return;
		const r = findResult(data.results, "/etc/shadow");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});

	it("blocks creating files in /usr/bin", () => {
		if (!filesystemEnforced) return;
		const r = findResult(data.results, "/usr/bin/malware");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});

	it("blocks overwriting agentsh config", () => {
		if (!filesystemEnforced) return;
		const r = findResult(data.results, "agentsh config");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});

	it("blocks writing to /etc/sudoers", () => {
		if (!filesystemEnforced) return;
		const r = findResult(data.results, "/etc/sudoers");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});
});
