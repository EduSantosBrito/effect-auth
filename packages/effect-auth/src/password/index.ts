import { Context, Effect, Layer, Match, Redacted, Schema } from "effect";
import {
  randomBytes as nodeRandomBytes,
  scrypt as nodeScrypt,
  timingSafeEqual as nodeTimingSafeEqual,
} from "node:crypto";
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
const decodePasswordHash = Schema.decodeUnknownEffect(PasswordHash);

export interface NativeScryptRuntime {
  readonly randomBytes?: (size: number) => Buffer;
  readonly scrypt?: typeof nodeScrypt;
  readonly timingSafeEqual?: (left: Buffer, right: Buffer) => boolean;
}

const nodeScryptRuntime: NativeScryptRuntime = {
  randomBytes: nodeRandomBytes,
  scrypt: nodeScrypt,
  timingSafeEqual: nodeTimingSafeEqual,
};

const requireNativeScryptRuntime = (
  runtime: NativeScryptRuntime,
): Effect.Effect<Required<NativeScryptRuntime>, PasswordHashFailure> =>
  runtime.randomBytes && runtime.scrypt && runtime.timingSafeEqual
    ? Effect.succeed({
        randomBytes: runtime.randomBytes,
        scrypt: runtime.scrypt,
        timingSafeEqual: runtime.timingSafeEqual,
      })
    : Effect.fail(new PasswordHashFailure({ reason: "UnsupportedRuntime" }));

const scryptEffect = (
  scrypt: typeof nodeScrypt,
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
  });

const validatePassword = Match.type<{
  readonly value: string;
  readonly email: NormalizedEmail;
  readonly localPart: string;
}>().pipe(
  Match.when({ value: (value) => value.length < 12 }, () =>
    new PasswordPolicyFailure({ reason: "TooShort" }),
  ),
  Match.when({ value: (value) => value.length > 128 }, () =>
    new PasswordPolicyFailure({ reason: "TooLong" }),
  ),
  Match.when(({ value, email }) => value === email, () =>
    new PasswordPolicyFailure({ reason: "MatchesEmail" }),
  ),
  Match.when(({ value, localPart }) => value === localPart, () =>
    new PasswordPolicyFailure({ reason: "MatchesEmailLocalPart" }),
  ),
  Match.orElse(() => undefined),
);

export const SecureDefaultPasswordPolicy = Layer.succeed(PasswordPolicy)({
  validate: ({ email, password }) => {
    const value = Redacted.value(password);
    const localPart = String(email).split("@")[0] ?? "";
    const failure = validatePassword({ value, email, localPart });
    return failure === undefined ? Effect.void : Effect.fail(failure);
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

export const makeNativeScryptPasswordHasher = (
  runtime: NativeScryptRuntime = nodeScryptRuntime,
): PasswordHasherShape => ({
  hash: (password) =>
    Effect.gen(function* () {
      const native = yield* requireNativeScryptRuntime(runtime);
      const salt = native.randomBytes(16);
      const derived = yield* scryptEffect(
        native.scrypt,
        Redacted.value(password),
        salt,
        params,
        params.dkLen,
      );
      return yield* decodePasswordHash(
        `$effect-auth-scrypt$N=${params.N},r=${params.r},p=${params.p},dkLen=${params.dkLen}$${salt.toString("base64url")}$${derived.toString("base64url")}`,
      ).pipe(Effect.mapError(() => new PasswordHashFailure({ reason: "HashingFailed" })));
    }),
  verify: ({ password, hash }) =>
    Effect.gen(function* () {
      const native = yield* requireNativeScryptRuntime(runtime);
      const parsed = parseHash(hash);
      if (!parsed) return yield* new PasswordHashFailure({ reason: "MalformedHash" });
      const derived = yield* scryptEffect(
        native.scrypt,
        Redacted.value(password),
        parsed.salt,
        parsed,
        parsed.dkLen,
      );
      return (
        derived.length === parsed.derivedKey.length &&
        native.timingSafeEqual(derived, parsed.derivedKey)
      );
    }),
});

export const NativeScryptPasswordHasher = Layer.succeed(PasswordHasher)(
  makeNativeScryptPasswordHasher(),
);
