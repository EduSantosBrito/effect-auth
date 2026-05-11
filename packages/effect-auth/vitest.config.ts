import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["**/.repos/**", "**/dist/**", "**/node_modules/**"],
  },
});
