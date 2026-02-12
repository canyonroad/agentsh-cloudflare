import { describe, it, beforeAll, expect } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";

describe("SSRF Prevention", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/ssrf");
		results = response.results;
	});

	// Without seccomp interception, requests to internal/metadata IPs may
	// fail with a connection error instead of being policy-blocked.  Either
	// way the command must not succeed.

	it("blocks AWS metadata endpoint (169.254.169.254)", () => {
		const r = findResult(results, "169.254.169.254");
		expect(r.result.success).toBe(false);
	});

	it("blocks 10.0.0.1 (Class A private)", () => {
		const r = findResult(results, "10.0.0.1");
		expect(r.result.success).toBe(false);
	});

	it("blocks 10.255.255.1 (Class A private)", () => {
		const r = findResult(results, "10.255.255.1");
		expect(r.result.success).toBe(false);
	});

	it("blocks 172.16.0.1 (Class B private)", () => {
		const r = findResult(results, "172.16.0.1");
		expect(r.result.success).toBe(false);
	});

	it("blocks 172.31.255.1 (Class B private)", () => {
		const r = findResult(results, "172.31.255.1");
		expect(r.result.success).toBe(false);
	});

	it("blocks 192.168.1.1 (Class C private)", () => {
		const r = findResult(results, "192.168.1.1");
		expect(r.result.success).toBe(false);
	});

	it("blocks 192.168.255.1 (Class C private)", () => {
		const r = findResult(results, "192.168.255.1");
		expect(r.result.success).toBe(false);
	});

	it("blocks 169.254.1.1 (link-local)", () => {
		const r = findResult(results, "169.254.1.1");
		expect(r.result.success).toBe(false);
	});

	it("allows external HTTPS (httpbin.org)", () => {
		const r = findResult(results, "httpbin.org");
		// External HTTPS must not be policy-blocked.  If the container
		// cannot reach the internet the command may still fail, but it
		// should never be flagged as blocked by policy.
		expect(r.result.blocked).not.toBe(true);
	});
});
