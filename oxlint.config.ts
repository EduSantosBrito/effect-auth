import { defineConfig } from "oxlint";
import { strict } from "effect-rules/configs";

export default defineConfig({
  ...strict,
  ignorePatterns: ["**/dist/**", "**/node_modules/**", ".repos/**"],
});
