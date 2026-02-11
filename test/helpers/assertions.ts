import { expect } from "vitest";
import type { ExecuteResult } from "./sandbox";

/** Assert that a command was blocked by agentsh policy. */
export function expectBlocked(result: ExecuteResult, ruleName?: string) {
	expect(result.blocked).toBe(true);
	expect(result.success).toBe(false);
	if (ruleName) {
		expect(result.message).toContain(ruleName);
	}
}

/** Assert that a command was allowed and succeeded. */
export function expectAllowed(result: ExecuteResult) {
	expect(result.blocked).toBe(false);
	expect(result.success).toBe(true);
	expect(result.exitCode).toBe(0);
}

/** Assert that a command's stdout contains the given text. */
export function expectOutputContains(result: ExecuteResult, text: string) {
	expect(result.stdout).toContain(text);
}
