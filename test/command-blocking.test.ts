import { describe, it, expect, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResponse } from "./helpers/sandbox";

describe("Command Blocking", () => {
	let data: DemoResponse;

	beforeAll(async () => {
		data = await fetchDemo("/demo/commands");
	}, 300_000);

	// Privilege Escalation
	it("blocks sudo id", () => {
		const r = findResult(data.results, "sudo id (privilege");
		expect(r.result.success).toBe(false);
	});

	it("blocks su (switch user)", () => {
		const r = findResult(data.results, "su (switch user");
		expect(r.result.success).toBe(false);
	});

	// SSH/Remote Access
	it("blocks ssh (remote login)", () => {
		const r = findResult(data.results, "ssh (remote login)");
		expect(r.result.success).toBe(false);
	});

	it("blocks scp (secure copy)", () => {
		const r = findResult(data.results, "scp (secure copy)");
		expect(r.result.success).toBe(false);
	});

	// System Admin
	it("blocks shutdown (halt system)", () => {
		const r = findResult(data.results, "shutdown (halt");
		expect(r.result.success).toBe(false);
	});

	it("blocks mount (mount filesystem)", () => {
		const r = findResult(data.results, "mount (mount filesystem)");
		expect(r.result.success).toBe(false);
	});

	// Network Tools
	it("blocks nc (netcat listener)", () => {
		const r = findResult(data.results, "nc (netcat listener)");
		expect(r.result.success).toBe(false);
	});

	it("blocks nmap (port scanner)", () => {
		const r = findResult(data.results, "nmap (port scanner)");
		expect(r.result.success).toBe(false);
	});

	// Process Control
	it("blocks killall agentsh", () => {
		const r = findResult(data.results, "killall agentsh");
		expect(r.result.success).toBe(false);
	});

	it("blocks pkill agentsh", () => {
		const r = findResult(data.results, "pkill agentsh");
		expect(r.result.success).toBe(false);
	});
});
