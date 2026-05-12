import { Clock, Context, Effect, Layer, Schema } from "effect";
import type { ClientIp, NormalizedEmail } from "../domain/index.js";

export const RateLimitBucket = Schema.Literals([
  "SignIn",
  "SignUp",
  "ResendVerification",
  "PasswordReset",
  "PasswordChange",
]);
export type RateLimitBucket = typeof RateLimitBucket.Type;

export class RateLimitExceeded extends Schema.TaggedErrorClass<RateLimitExceeded>()(
  "RateLimitExceeded",
  {
    bucket: RateLimitBucket,
    retryAfterMillis: Schema.Number,
  },
) {}

export interface RateLimitAttempt {
  readonly bucket: RateLimitBucket;
  readonly email?: NormalizedEmail;
  readonly ip?: ClientIp;
}

export class RateLimiter extends Context.Service<
  RateLimiter,
  {
    readonly check: (attempt: RateLimitAttempt) => Effect.Effect<void, RateLimitExceeded>;
  }
>()("effect-auth/RateLimiter") {}
export type RateLimiterShape = typeof RateLimiter.Service;

export const deriveRateLimitKey = (attempt: RateLimitAttempt): string =>
  [
    attempt.bucket,
    attempt.email ? `email:${attempt.email}` : undefined,
    attempt.ip ? `ip:${attempt.ip}` : undefined,
  ]
    .filter(Boolean)
    .join("|");

export const PermissiveDevRateLimiter = Layer.succeed(RateLimiter)({
  check: () => Effect.void,
});

export interface BoundedDevRateLimiterOptions {
  readonly limit?: number;
  readonly windowMillis?: number;
}

export const makeBoundedDevRateLimiter = (
  options: BoundedDevRateLimiterOptions = {},
): RateLimiterShape => {
  const limit = options.limit ?? 100;
  const windowMillis = options.windowMillis ?? 10_000;
  const attempts = new Map<string, Array<number>>();
  return {
    check: (attempt) =>
      Effect.gen(function* () {
        const now = yield* Clock.currentTimeMillis;
        const key = deriveRateLimitKey(attempt);
        const retained = (attempts.get(key) ?? []).filter((at) => at + windowMillis > now);
        const oldest = retained[0];
        if (retained.length >= limit && oldest !== undefined) {
          const retryAfterMillis = Math.max(1, oldest + windowMillis - now);
          return yield* new RateLimitExceeded({ bucket: attempt.bucket, retryAfterMillis });
        }
        retained.push(now);
        attempts.set(key, retained);
      }),
  };
};

export const BoundedDevRateLimiter = (options?: BoundedDevRateLimiterOptions) =>
  Layer.succeed(RateLimiter)(makeBoundedDevRateLimiter(options));
