export {
  Auth,
  AuthLive,
  type AuthShape,
  type ChangePasswordInput,
  type RequestPasswordResetInput,
  type ResetPasswordInput,
  type SignInInput,
  type SignUpInput,
} from "./auth.js";
export type { PublicAuthError } from "./domain/index.js";
export {
  VerificationTokenConfig,
  VerificationTokenConfigLive,
  SessionPolicy,
  SessionPolicyLive,
  type ListedSession,
  type ListSessionsInput,
  type ListSessionsResult,
  type RevokeUserSessionInput,
  type SessionPolicyInput,
  type SessionPolicyShape,
  type VerificationTokenConfigInput,
  type VerificationTokenConfigShape,
} from "./workflows/index.js";

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
