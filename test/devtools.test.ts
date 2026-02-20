import { describe, it, expect, beforeAll } from "vitest";
import { fetchDemo, findResult, type DemoResult } from "./helpers/sandbox";
import {
	expectAllowed,
	expectOutputContains,
} from "./helpers/assertions";

describe("Dev Tools", () => {
	let results: DemoResult[];

	beforeAll(async () => {
		const response = await fetchDemo("/demo/devtools");
		results = response.results;
	});

	it("runs python3", () => {
		const r = findResult(results, "Python version");
		expectAllowed(r.result);
		expectOutputContains(r.result, "Python");
	});

	it("runs python3 inline code", () => {
		const r = findResult(results, "Python JSON");
		expectAllowed(r.result);
		expectOutputContains(r.result, "hello");
	});

	it("runs node", () => {
		const r = findResult(results, "Node.js version");
		expectAllowed(r.result);
	});

	it("runs node inline code (may timeout in Firecracker)", () => {
		const r = findResult(results, "Node.js inline");
		// Node.js -e triggers full V8 startup with hundreds of openat() calls,
		// each intercepted by seccomp_unotify. In Firecracker this can exceed
		// the command timeout. We verify it ran (not blocked by policy).
		expect(r.result.blocked).toBe(false);
	});

	it("runs bun", () => {
		const r = findResult(results, "Bun version");
		expectAllowed(r.result);
	});

	it("lists pip3 packages", () => {
		const r = findResult(results, "Python packages");
		expectAllowed(r.result);
	});

	it("runs git", () => {
		const r = findResult(results, "Git version");
		expectAllowed(r.result);
		expectOutputContains(r.result, "git version");
	});

	it("curls external HTTPS API", () => {
		const r = findResult(results, "GitHub API");
		expectAllowed(r.result);
	});

	it("supports pipe operations", () => {
		const r = findResult(results, "Pipe operations");
		expectAllowed(r.result);
		expectOutputContains(r.result, "SELECT");
	});

	it("has /workspace directory", () => {
		const r = findResult(results, "Workspace directory");
		expectAllowed(r.result);
	});
});
