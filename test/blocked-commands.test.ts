import { describe, it, beforeAll, expect } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";

describe("Blocked Commands", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/blocked");
		results = response.results;
	});

	it("prevents nc from running (not installed)", () => {
		const r = findResult(results, "nc -h");
		expect(r.result.success).toBe(false);
		expect(r.result.exitCode).not.toBe(0);
	});

	it("prevents nmap from running (not installed)", () => {
		const r = findResult(results, "nmap");
		expect(r.result.success).toBe(false);
		expect(r.result.exitCode).not.toBe(0);
	});

	it("blocks curl to cloud metadata by policy", () => {
		const r = findResult(results, "metadata");
		// May be policy-blocked or connection-refused without seccomp
		expect(r.result.success).toBe(false);
	});
});
