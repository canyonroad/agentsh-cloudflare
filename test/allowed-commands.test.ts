import { describe, it, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";
import {
	expectAllowed,
	expectOutputContains,
} from "./helpers/assertions";

describe("Allowed Commands", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/allowed");
		results = response.results;
	});

	it("allows whoami", () => {
		const r = findResult(results, "whoami");
		expectAllowed(r.result);
	});

	it("allows pwd", () => {
		const r = findResult(results, "pwd");
		expectAllowed(r.result);
	});

	it("allows ls -la /workspace", () => {
		const r = findResult(results, "ls -la /workspace");
		expectAllowed(r.result);
	});

	it("allows echo", () => {
		const r = findResult(results, "echo");
		expectAllowed(r.result);
		expectOutputContains(r.result, "Hello from agentsh sandbox!");
	});
});
