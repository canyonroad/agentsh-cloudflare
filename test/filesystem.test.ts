import { describe, it, expect, beforeAll } from "vitest";
import {
	fetchDemo,
	findResult,
	type DemoResponse,
} from "./helpers/sandbox";
import { expectAllowed } from "./helpers/assertions";

describe("Filesystem Protection", () => {
	let data: DemoResponse;
	let fuseAvailable: boolean;

	beforeAll(async () => {
		data = await fetchDemo("/demo/filesystem");
		// Check if FUSE is available in the environment
		const detectResult = findResult(data.results, "FUSE status");
		fuseAvailable = detectResult.result.stdout.includes("fuse") &&
			detectResult.result.stdout.includes("✓");
	}, 120_000);

	it("reports FUSE status", () => {
		const r = findResult(data.results, "FUSE status");
		expect(r.result.success).toBe(true);
		expect(r.result.stdout).toContain("fuse");
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
		if (!fuseAvailable) return; // skip without FUSE - root can write to /etc
		const r = findResult(data.results, "/etc/passwd");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks reading /etc/shadow", () => {
		if (!fuseAvailable) return; // skip without FUSE - root can read /etc/shadow
		const r = findResult(data.results, "/etc/shadow");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied/i,
		);
	});

	it("blocks creating files in /usr/bin", () => {
		if (!fuseAvailable) return; // skip without FUSE
		const r = findResult(data.results, "/usr/bin/malware");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks path traversal to /etc/shadow", () => {
		if (!fuseAvailable) return; // skip without FUSE
		const r = findResult(data.results, "traversal");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied|No such file/i,
		);
	});

	it("blocks overwriting agentsh config", () => {
		if (!fuseAvailable) return; // skip without FUSE
		const r = findResult(data.results, "agentsh config");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|read-only|BLOCKED|denied/i,
		);
	});

	it("blocks writing to /etc/sudoers", () => {
		if (!fuseAvailable) return; // skip without FUSE
		const r = findResult(data.results, "/etc/sudoers");
		expect(r.result.stdout + r.result.stderr).toMatch(
			/permission denied|BLOCKED|denied/i,
		);
	});
});
