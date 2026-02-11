import { describe, it, beforeAll, expect } from "vitest";
import { fetchDemo, type DemoResult } from "./helpers/sandbox";

describe("DLP Redaction", () => {
	// Note: DLP only works on API proxy traffic, not on command stdout.
	// These tests document the current behavior where secrets echo to stdout
	// without redaction. Full DLP requires routing API calls through the agentsh proxy.

	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/dlp");
		results = response.results;
	});

	it("echoes OpenAI key (DLP only on proxy traffic)", () => {
		const r = results[0];
		expect(r.result.success).toBe(true);
		expect(r.result.blocked).toBe(false);
	});

	it("echoes AWS key (DLP only on proxy traffic)", () => {
		const r = results[1];
		expect(r.result.success).toBe(true);
		expect(r.result.blocked).toBe(false);
	});

	it("echoes GitHub token (DLP only on proxy traffic)", () => {
		const r = results[2];
		expect(r.result.success).toBe(true);
		expect(r.result.blocked).toBe(false);
	});

	it("echoes email/phone (DLP only on proxy traffic)", () => {
		const r = results[3];
		expect(r.result.success).toBe(true);
		expect(r.result.blocked).toBe(false);
	});
});
