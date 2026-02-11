import { describe, it, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";
import { expectBlocked, expectAllowed } from "./helpers/assertions";

describe("SSRF Prevention", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/ssrf");
		results = response.results;
	});

	it("blocks AWS metadata endpoint (169.254.169.254)", () => {
		const r = findResult(results, "169.254.169.254");
		expectBlocked(r.result);
	});

	it("blocks 10.0.0.1 (Class A private)", () => {
		const r = findResult(results, "10.0.0.1");
		expectBlocked(r.result);
	});

	it("blocks 10.255.255.1 (Class A private)", () => {
		const r = findResult(results, "10.255.255.1");
		expectBlocked(r.result);
	});

	it("blocks 172.16.0.1 (Class B private)", () => {
		const r = findResult(results, "172.16.0.1");
		expectBlocked(r.result);
	});

	it("blocks 172.31.255.1 (Class B private)", () => {
		const r = findResult(results, "172.31.255.1");
		expectBlocked(r.result);
	});

	it("blocks 192.168.1.1 (Class C private)", () => {
		const r = findResult(results, "192.168.1.1");
		expectBlocked(r.result);
	});

	it("blocks 192.168.255.1 (Class C private)", () => {
		const r = findResult(results, "192.168.255.1");
		expectBlocked(r.result);
	});

	it("blocks 169.254.1.1 (link-local)", () => {
		const r = findResult(results, "169.254.1.1");
		expectBlocked(r.result);
	});

	it("allows external HTTPS (httpbin.org)", () => {
		const r = findResult(results, "httpbin.org");
		expectAllowed(r.result);
	});
});
