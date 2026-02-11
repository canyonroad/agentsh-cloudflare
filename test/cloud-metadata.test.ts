import { describe, it, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";
import { expectBlocked } from "./helpers/assertions";

describe("Cloud Metadata Protection", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/cloud-metadata");
		results = response.results;
	});

	it("blocks AWS EC2 metadata (169.254.169.254)", () => {
		const r = findResult(results, "AWS");
		expectBlocked(r.result);
	});

	it("blocks GCP metadata (metadata.google.internal)", () => {
		const r = findResult(results, "GCP");
		expectBlocked(r.result);
	});

	it("blocks Azure IMDS", () => {
		const r = findResult(results, "Azure");
		expectBlocked(r.result);
	});

	it("blocks DigitalOcean metadata", () => {
		const r = findResult(results, "DigitalOcean");
		expectBlocked(r.result);
	});

	it("blocks Alibaba Cloud metadata (100.100.100.200)", () => {
		const r = findResult(results, "Alibaba");
		expectBlocked(r.result);
	});

	it("blocks Oracle Cloud metadata", () => {
		const r = findResult(results, "Oracle");
		expectBlocked(r.result);
	});
});
