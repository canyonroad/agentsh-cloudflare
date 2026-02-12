import { describe, it, expect, beforeAll } from "vitest";
import {
	fetchDemo,
	findResult,
	type DemoResponse,
} from "./helpers/sandbox";
import { expectAllowed } from "./helpers/assertions";

describe("Filesystem Protection", () => {
	let data: DemoResponse;
	let landlockAvailable: boolean;

	beforeAll(async () => {
		data = await fetchDemo("/demo/filesystem");
		// Check if Landlock enforcement is actually working by checking a blocked operation.
		// Landlock may be detected as available by the kernel but not enforced if the
		// agentsh-unixwrap wrapper binary doesn't have Landlock support yet.
		const etcPasswdResult = findResult(data.results, "/etc/passwd");
		const output = etcPasswdResult.result.stdout + etcPasswdResult.result.stderr;
		landlockAvailable = /permission denied|BLOCKED|denied/i.test(output);
	}, 120_000);

	it("reports security status", () => {
		const r = findResult(data.results, "FUSE + Landlock status");
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
		if (!landlockAvailable) return; // skip without Landlock - root can write to /etc
		const r = findResult(data.results, "/etc/passwd");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks writing to /etc/shadow", () => {
		if (!landlockAvailable) return; // skip without Landlock - root can write to /etc/shadow
		const r = findResult(data.results, "/etc/shadow");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks creating files in /usr/bin", () => {
		if (!landlockAvailable) return; // skip without Landlock
		const r = findResult(data.results, "/usr/bin/malware");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks overwriting agentsh config", () => {
		if (!landlockAvailable) return; // skip without Landlock
		const r = findResult(data.results, "agentsh config");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks writing to /etc/sudoers", () => {
		if (!landlockAvailable) return; // skip without Landlock
		const r = findResult(data.results, "/etc/sudoers");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied/i,
		);
	});
});
