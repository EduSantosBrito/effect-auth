import { Context, Effect, Layer, Redacted, Schema } from "effect";
import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import type { NormalizedEmail, PasswordText } from "../domain/index.js";

export const PasswordHash = Schema.RedactedFromValue(Schema.String, { label: "PasswordHash" });
export type PasswordHash = typeof PasswordHash.Type;

export class PasswordPolicyFailure extends Schema.TaggedErrorClass<PasswordPolicyFailure>()(
  "PasswordPolicyFailure",
  {
    reason: Schema.Literals(["TooShort", "TooLong", "MatchesEmail", "MatchesEmailLocalPart"]),
  },
) {}

export class PasswordHashFailure extends Schema.TaggedErrorClass<PasswordHashFailure>()(
  "PasswordHashFailure",
  {
    reason: Schema.Literals(["UnsupportedRuntime", "MalformedHash", "HashingFailed"]),
  },
) {}

export interface PasswordPolicyShape {
  readonly validate: (input: {
    readonly email: NormalizedEmail;
    readonly password: PasswordText;
  }) => Effect.Effect<void, PasswordPolicyFailure>;
}

export interface PasswordHasherShape {
  readonly hash: (password: PasswordText) => Effect.Effect<PasswordHash, PasswordHashFailure>;
  readonly verify: (input: {
    readonly password: PasswordText;
    readonly hash: PasswordHash;
  }) => Effect.Effect<boolean, PasswordHashFailure>;
}

export class PasswordPolicy extends Context.Service<PasswordPolicy, PasswordPolicyShape>()(
  "effect-auth/password/PasswordPolicy",
) {}
export class PasswordHasher extends Context.Service<PasswordHasher, PasswordHasherShape>()(
  "effect-auth/password/PasswordHasher",
) {}

const params: {
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly dkLen: number;
  readonly maxmem: number;
} = { N: 16384, r: 16, p: 1, dkLen: 64, maxmem: 128 * 1024 * 1024 };

const scryptEffect = (
  password: string,
  salt: Buffer,
  options: {
    readonly N: number;
    readonly r: number;
    readonly p: number;
    readonly maxmem?: number;
  },
  dkLen: number,
): Effect.Effect<Buffer, PasswordHashFailure> =>
  Effect.callback<Buffer, PasswordHashFailure>((resume) => {
    try {
      scrypt(
        password,
        salt,
        dkLen,
        {
          cost: options.N,
          blockSize: options.r,
          parallelization: options.p,
          maxmem: options.maxmem ?? params.maxmem,
        },
        (error, derivedKey) => {
          resume(
            error
              ? Effect.fail(new PasswordHashFailure({ reason: "HashingFailed" }))
              : Effect.succeed(Buffer.from(derivedKey)),
          );
        },
      );
    } catch {
      resume(Effect.fail(new PasswordHashFailure({ reason: "HashingFailed" })));
    }
  });

export const SecureDefaultPasswordPolicy = Layer.succeed(PasswordPolicy)({
  validate: ({ email, password }) => {
    const value = Redacted.value(password);
    const localPart = String(email).split("@")[0] ?? "";
    if (value.length < 12) return Effect.fail(new PasswordPolicyFailure({ reason: "TooShort" }));
    if (value.length > 128) return Effect.fail(new PasswordPolicyFailure({ reason: "TooLong" }));
    if (value === email) return Effect.fail(new PasswordPolicyFailure({ reason: "MatchesEmail" }));
    if (value === localPart)
      return Effect.fail(new PasswordPolicyFailure({ reason: "MatchesEmailLocalPart" }));
    return Effect.void;
  },
});

const parseHash = (hash: PasswordHash) => {
  const text = Redacted.value(hash);
  const match =
    /^\$effect-auth-scrypt\$N=(\d+),r=(\d+),p=(\d+),dkLen=(\d+)\$([A-Za-z0-9_-]+)\$([A-Za-z0-9_-]+)$/u.exec(
      text,
    );
  if (!match) return undefined;
  const [, N, r, p, dkLen, salt, derivedKey] = match;
  if (!N || !r || !p || !dkLen || !salt || !derivedKey) return undefined;
  return {
    N: Number(N),
    r: Number(r),
    p: Number(p),
    dkLen: Number(dkLen),
    salt: Buffer.from(salt, "base64url"),
    derivedKey: Buffer.from(derivedKey, "base64url"),
  };
};

export const NativeScryptPasswordHasher = Layer.succeed(PasswordHasher)({
  hash: (password) =>
    Effect.gen(function* () {
      const salt = randomBytes(16);
      const derived = yield* scryptEffect(Redacted.value(password), salt, params, params.dkLen);
      return yield* Schema.decodeUnknownEffect(PasswordHash)(
        `$effect-auth-scrypt$N=${params.N},r=${params.r},p=${params.p},dkLen=${params.dkLen}$${salt.toString("base64url")}$${derived.toString("base64url")}`,
      ).pipe(Effect.mapError(() => new PasswordHashFailure({ reason: "HashingFailed" })));
    }),
  verify: ({ password, hash }) =>
    Effect.gen(function* () {
      const parsed = parseHash(hash);
      if (!parsed) return yield* new PasswordHashFailure({ reason: "MalformedHash" });
      const derived = yield* scryptEffect(
        Redacted.value(password),
        parsed.salt,
        parsed,
        parsed.dkLen,
      );
      return (
        derived.length === parsed.derivedKey.length && timingSafeEqual(derived, parsed.derivedKey)
      );
    }),
});
