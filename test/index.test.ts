import { assert, it } from "@effect/vitest";
import * as Effect from "effect/Effect";
import { createEffectAuthClient } from "../src/index";

it.effect("creates effect-auth client", () =>
  Effect.sync(() => {
    const baseUrl = new URL("https://auth.example.com");

    assert.deepStrictEqual(createEffectAuthClient({ baseUrl }), { baseUrl });
  }),
);
