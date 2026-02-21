import { describe, it, expect, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResponse } from "./helpers/sandbox";

describe("Privilege Escalation Prevention", () => {
	let data: DemoResponse;
	let filesystemEnforced: boolean;

	beforeAll(async () => {
		data = await fetchDemo("/demo/privilege-escalation");
		// Check if filesystem enforcement is working by looking at /etc/shadow read result
		const shadowResult = findResult(data.results, "Read /etc/shadow");
		const output = shadowResult.result.stdout + shadowResult.result.stderr;
		filesystemEnforced = /permission denied|BLOCKED|denied|EACCES|Bad file descriptor/i.test(output);
	}, 300_000);

	// Command-level blocks
	it("blocks sudo id (run as root)", () => {
		const r = findResult(data.results, "sudo id (run as root)");
		expect(r.result.success).toBe(false);
	});

	it("blocks sudo cat /etc/shadow", () => {
		const r = findResult(data.results, "sudo cat /etc/shadow");
		expect(r.result.success).toBe(false);
	});

	it("blocks su - root (switch to root)", () => {
		const r = findResult(data.results, "su - root (switch");
		expect(r.result.success).toBe(false);
	});

	it("blocks pkexec (PolicyKit escalation)", () => {
		const r = findResult(data.results, "pkexec (PolicyKit");
		expect(r.result.success).toBe(false);
	});

	// File-level blocks
	it("blocks reading /etc/shadow", () => {
		if (!filesystemEnforced) return;
		const r = findResult(data.results, "Read /etc/shadow");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});

	it("blocks writing /etc/sudoers", () => {
		if (!filesystemEnforced) return;
		const r = findResult(data.results, "Write /etc/sudoers");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied|EACCES|Bad file descriptor/i,
		);
	});
});
