import { expect, test } from "@effect/vitest";
import { createEffectAuthClient } from "../src/index";

test("creates effect-auth client", () => {
  const baseUrl = new URL("https://auth.example.com");

  expect(createEffectAuthClient({ baseUrl })).toEqual({ baseUrl });
});
