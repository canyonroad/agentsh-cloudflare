import { describe, it, beforeAll, expect } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";
import { expectOutputContains } from "./helpers/assertions";

describe("agentsh Installation", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/allowed");
		results = response.results;
	});

	it("has agentsh installed and reports version", () => {
		const r = findResult(results, "agentsh --version");
		expect(r.result.success).toBe(true);
		expect(r.result.exitCode).toBe(0);
		// Version should be a semver-like string (e.g. "0.9.2")
		expect(r.result.stdout).toMatch(/\d+\.\d+\.\d+/);
	});

	it("has agentsh on PATH", () => {
		const r = findResult(results, "which agentsh");
		expect(r.result.success).toBe(true);
		expect(r.result.exitCode).toBe(0);
		expectOutputContains(r.result, "agentsh");
	});

	it("has agentsh config directory", () => {
		const r = findResult(results, "ls -la /etc/agentsh");
		expect(r.result.success).toBe(true);
		expect(r.result.exitCode).toBe(0);
		expectOutputContains(r.result, "config.yaml");
	});

	it("has agentsh security capabilities", () => {
		const r = findResult(results, "agentsh detect");
		expect(r.result.success).toBe(true);
		expect(r.result.exitCode).toBe(0);
	});
});
