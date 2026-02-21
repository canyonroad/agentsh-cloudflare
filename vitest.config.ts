import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		testTimeout: 120_000,
		hookTimeout: 300_000,
		include: ["test/**/*.test.ts"],
		globalSetup: ["test/global-setup.ts"],
		fileParallelism: false,
	},
});
