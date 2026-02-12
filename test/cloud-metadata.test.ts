import { describe, it, beforeAll, expect } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";

describe("Cloud Metadata Protection", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/cloud-metadata");
		results = response.results;
	});

	// Without seccomp interception, metadata requests may fail with a
	// connection error rather than being policy-blocked.  Either way the
	// command must not succeed.

	it("blocks AWS EC2 metadata (169.254.169.254)", () => {
		const r = findResult(results, "AWS");
		expect(r.result.success).toBe(false);
	});

	it("blocks GCP metadata (metadata.google.internal)", () => {
		const r = findResult(results, "GCP");
		expect(r.result.success).toBe(false);
	});

	it("blocks Azure IMDS", () => {
		const r = findResult(results, "Azure");
		expect(r.result.success).toBe(false);
	});

	it("blocks DigitalOcean metadata", () => {
		const r = findResult(results, "DigitalOcean");
		expect(r.result.success).toBe(false);
	});

	it("blocks Alibaba Cloud metadata (100.100.100.200)", () => {
		const r = findResult(results, "Alibaba");
		expect(r.result.success).toBe(false);
	});

	it("blocks Oracle Cloud metadata", () => {
		const r = findResult(results, "Oracle");
		expect(r.result.success).toBe(false);
	});
});
