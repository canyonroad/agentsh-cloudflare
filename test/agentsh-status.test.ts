import { describe, it, expect, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResponse } from "./helpers/sandbox";

describe("agentsh Status", () => {
	let data: DemoResponse;

	beforeAll(async () => {
		data = await fetchDemo("/demo/status");
	}, 600_000);

	it("reports agentsh version", () => {
		const r = findResult(data.results, "agentsh version");
		expect(r.result.success).toBe(true);
		expect(r.result.stdout).toMatch(/agentsh|v?\d+\.\d+/);
	});

	it("finds agentsh binary", () => {
		const r = findResult(data.results, "binary location");
		expect(r.result.success).toBe(true);
		expect(r.result.stdout).toContain("agentsh");
	});

	it("runs agentsh detect", () => {
		const r = findResult(data.results, "security capabilities");
		expect(r.result.success).toBe(true);
	});

	it("lists config directory", () => {
		const r = findResult(data.results, "Config directory");
		expect(r.result.success).toBe(true);
	});

	it("lists policies directory", () => {
		const r = findResult(data.results, "Policies directory");
		expect(r.result.success).toBe(true);
	});

	it("shows policy file header", () => {
		const r = findResult(data.results, "Policy file header");
		expect(r.result.success).toBe(true);
	});

	it("reports kernel version", () => {
		const r = findResult(data.results, "Kernel version");
		expect(r.result.success).toBe(true);
		expect(r.result.stdout).toMatch(/\d+\.\d+/);
	});
});
