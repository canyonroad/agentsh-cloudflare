export const BASE_URL =
	process.env.TEST_BASE_URL ||
	`http://localhost:${process.env.TEST_PORT || "8686"}`;

export interface ExecuteResult {
	success: boolean;
	stdout: string;
	stderr: string;
	exitCode: number;
	blocked?: boolean;
	message?: string;
}

export interface DemoResult {
	command: string;
	result: ExecuteResult;
}

export interface DemoResponse {
	results: DemoResult[];
	title?: string;
	description?: string;
	note?: string;
	blocked?: number;
	policyPath?: string;
}

/** Fetch a demo endpoint and return the parsed response.
 *  Uses AbortController to ensure the fetch is properly cancelled on timeout,
 *  preventing zombie requests from blocking the sandbox. */
export async function fetchDemo(path: string, timeoutMs = 290_000): Promise<DemoResponse> {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), timeoutMs);
	try {
		const res = await fetch(`${BASE_URL}${path}`, { signal: controller.signal });
		if (!res.ok) {
			throw new Error(`Demo fetch failed: ${res.status} ${await res.text()}`);
		}
		return (await res.json()) as DemoResponse;
	} finally {
		clearTimeout(timer);
	}
}

/** Execute a single command via the /execute endpoint. */
export async function executeCommand(command: string): Promise<ExecuteResult> {
	const res = await fetch(`${BASE_URL}/execute`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ command, turnstileToken: "test" }),
	});
	if (!res.ok) {
		throw new Error(
			`Execute failed: ${res.status} ${await res.text()}`,
		);
	}
	return (await res.json()) as ExecuteResult;
}

/** Find a result by substring match on the command field. */
export function findResult(
	results: DemoResult[],
	substring: string,
): DemoResult {
	const found = results.find((r) =>
		r.command.toLowerCase().includes(substring.toLowerCase()),
	);
	if (!found) {
		const available = results.map((r) => r.command).join(", ");
		throw new Error(
			`No result matching "${substring}" found. Available: ${available}`,
		);
	}
	return found;
}
