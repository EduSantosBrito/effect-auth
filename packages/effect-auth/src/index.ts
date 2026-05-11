export { Auth, AuthLive, type AuthShape } from "./auth.js";
export type { PublicAuthError } from "./domain/index.js";

export const packageName = "effect-auth";

export type EffectAuthClientOptions = {
  readonly baseUrl: URL;
};

export type EffectAuthClient = {
  readonly baseUrl: URL;
};

export const createEffectAuthClient = (options: EffectAuthClientOptions): EffectAuthClient => ({
  baseUrl: options.baseUrl,
});
