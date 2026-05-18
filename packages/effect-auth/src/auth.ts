import { Context, Duration, Effect, Layer, Option, Predicate, Redacted, Schema } from "effect";
import {
  AuthBoundary,
  AuthBoundaryLive,
  BoundaryParseError,
  type ClientIp,
  type PublicAuthError,
} from "./domain/index.js";
import { AuthEmail, type AuthEmailFailure } from "./email/index.js";
import {
  NativeScryptPasswordHasher,
  SecureDefaultPasswordPolicy,
  type PasswordHashFailure,
  type PasswordPolicyFailure,
} from "./password/index.js";
import { RateLimiter, type RateLimitExceeded } from "./rate-limit/index.js";
import { AuthStorage, type AuthStorageFailure } from "./storage/index.js";
import {
  AuthTokenLive,
  SessionToken,
  VerificationToken,
  type TokenGenerationFailure,
} from "./token/index.js";
import {
  EmailPasswordWorkflows,
  EmailPasswordWorkflowsLive,
  IdentityWorkflows,
  IdentityWorkflowsLive,
  PasswordRecoveryWorkflows,
  PasswordRecoveryWorkflowsLive,
  SessionPolicy,
  SessionWorkflows,
  SessionWorkflowsLive,
  VerificationTokenConfig,
  type ChangePasswordInput as ChangePasswordCommand,
  type ChangePasswordResult,
  type CurrentSessionInput as CurrentSessionCommand,
  type ListAccountsResult,
  type ListSessionsInput,
  type ListSessionsResult,
  type RequestPasswordResetInput as RequestPasswordResetCommand,
  type RevokeUserSessionInput as RevokeUserSessionCommand,
  type ResendVerificationInput,
  type ResetPasswordInput as ResetPasswordCommand,
  type SessionLookupResult,
  type SignInInput as SignInCommand,
  type SignInResult,
  type SignOutInput as SignOutCommand,
  type SignUpInput as SignUpCommand,
  type SignUpResult,
  type UpdateUserInput as UpdateUserCommand,
  type UpdateUserResult,
  type VerifyEmailInput as VerifyEmailCommand,
  type VerifyEmailResult,
} from "./workflows/index.js";

export interface AuthLiveConfigInput {
  readonly session?: {
    readonly ttl?: Duration.Input;
    readonly updateAge?: Duration.Input;
  };
  readonly verification?: {
    readonly emailVerificationTtl?: Duration.Input;
    readonly passwordResetTtl?: Duration.Input;
  };
  readonly encryptionKey?: Redacted.Redacted<string>;
  readonly encryptionKeyId?: string;
  readonly providerTokens?: {
    readonly encryptionKey?: Redacted.Redacted<string>;
    readonly encryptionKeyId?: string;
  };
  readonly oauthState?: {
    readonly ttl?: Duration.Input;
    readonly encryptionKey?: Redacted.Redacted<string>;
    readonly encryptionKeyId?: string;
  };
  readonly oauth?: {
    readonly allowDifferentEmailLinking?: boolean;
  };
}

export interface AuthLiveConfigShape {
  readonly session: {
    readonly ttlMillis: number;
    readonly updateAgeMillis: number;
  };
  readonly verification: {
    readonly emailVerificationTtlMillis: number;
    readonly passwordResetTtlMillis: number;
  };
  readonly encryptionKey: Option.Option<Redacted.Redacted<string>>;
  readonly encryptionKeyId: string;
  readonly providerTokens: {
    readonly encryptionKey: Option.Option<Redacted.Redacted<string>>;
    readonly encryptionKeyId: string;
  };
  readonly oauthState: {
    readonly ttlMillis: number;
    readonly encryptionKey: Option.Option<Redacted.Redacted<string>>;
    readonly encryptionKeyId: string;
  };
  readonly oauth: {
    readonly allowDifferentEmailLinking: boolean;
  };
}

const optionalRedacted = <A>(
  value: Redacted.Redacted<A> | undefined,
): Option.Option<Redacted.Redacted<A>> =>
  value === undefined ? Option.none() : Option.some(value);

const positiveFiniteDurationMillis = (
  input: Duration.Input,
  field: string,
): Effect.Effect<number, BoundaryParseError> => {
  const millis = Duration.toMillis(input);
  return Number.isFinite(millis) && millis > 0
    ? Effect.succeed(millis)
    : Effect.fail(new BoundaryParseError({ field, reason: "Expected positive finite duration" }));
};

const parseAuthLiveConfig = Effect.fn("AuthLiveConfig.parse")(function* (
  input: AuthLiveConfigInput = {},
) {
  const sessionTtlMillis = yield* positiveFiniteDurationMillis(
    input.session?.ttl ?? Duration.days(7),
    "session.ttl",
  );
  const sessionUpdateAgeMillis = yield* positiveFiniteDurationMillis(
    input.session?.updateAge ?? Duration.days(1),
    "session.updateAge",
  );
  const emailVerificationTtlMillis = yield* positiveFiniteDurationMillis(
    input.verification?.emailVerificationTtl ?? Duration.days(1),
    "verification.emailVerificationTtl",
  );
  const passwordResetTtlMillis = yield* positiveFiniteDurationMillis(
    input.verification?.passwordResetTtl ?? Duration.minutes(15),
    "verification.passwordResetTtl",
  );
  const oauthStateTtlMillis = yield* positiveFiniteDurationMillis(
    input.oauthState?.ttl ?? Duration.minutes(10),
    "oauthState.ttl",
  );
  const encryptionKeyId = input.encryptionKeyId ?? "default";
  return {
    session: {
      ttlMillis: sessionTtlMillis,
      updateAgeMillis: sessionUpdateAgeMillis,
    },
    verification: {
      emailVerificationTtlMillis,
      passwordResetTtlMillis,
    },
    encryptionKey: optionalRedacted(input.encryptionKey),
    encryptionKeyId,
    providerTokens: {
      encryptionKey: optionalRedacted(input.providerTokens?.encryptionKey),
      encryptionKeyId: input.providerTokens?.encryptionKeyId ?? encryptionKeyId,
    },
    oauthState: {
      ttlMillis: oauthStateTtlMillis,
      encryptionKey: optionalRedacted(input.oauthState?.encryptionKey),
      encryptionKeyId: input.oauthState?.encryptionKeyId ?? encryptionKeyId,
    },
    oauth: {
      allowDifferentEmailLinking: input.oauth?.allowDifferentEmailLinking ?? false,
    },
  } satisfies AuthLiveConfigShape;
});

export class AuthLiveConfig extends Context.Service<
  AuthLiveConfig,
  {
    readonly session: {
      readonly ttlMillis: number;
      readonly updateAgeMillis: number;
    };
    readonly verification: {
      readonly emailVerificationTtlMillis: number;
      readonly passwordResetTtlMillis: number;
    };
    readonly encryptionKey: Option.Option<Redacted.Redacted<string>>;
    readonly encryptionKeyId: string;
    readonly providerTokens: {
      readonly encryptionKey: Option.Option<Redacted.Redacted<string>>;
      readonly encryptionKeyId: string;
    };
    readonly oauthState: {
      readonly ttlMillis: number;
      readonly encryptionKey: Option.Option<Redacted.Redacted<string>>;
      readonly encryptionKeyId: string;
    };
    readonly oauth: {
      readonly allowDifferentEmailLinking: boolean;
    };
  }
>()("effect-auth/AuthLiveConfig") {
  static readonly layer = (input?: AuthLiveConfigInput) =>
    Layer.effect(AuthLiveConfig)(parseAuthLiveConfig(input));
}

export interface SignUpInput {
  readonly email: unknown;
  readonly password: unknown;
  readonly name: unknown;
  readonly verificationCallbackUrl: unknown;
  readonly ip?: unknown;
}

export interface SignInInput {
  readonly email: unknown;
  readonly password: unknown;
  readonly ip?: unknown;
  readonly userAgent?: string;
}

export interface VerifyEmailInput {
  readonly token: unknown;
}

export interface SessionTokenInput {
  readonly sessionToken: unknown;
}

export interface RevokeUserSessionInput {
  readonly sessionToken: unknown;
  readonly sessionId: RevokeUserSessionCommand["sessionId"];
}

export interface RequestPasswordResetInput {
  readonly email: unknown;
  readonly resetCallbackUrl: unknown;
  readonly ip?: unknown;
}

export interface ResetPasswordInput {
  readonly token: unknown;
  readonly password: unknown;
}

export interface ChangePasswordInput {
  readonly sessionToken: unknown;
  readonly currentPassword: unknown;
  readonly newPassword: unknown;
  readonly ip?: unknown;
}

export interface DeleteUserInput {
  readonly sessionToken: unknown;
  readonly password: unknown;
  readonly ip?: unknown;
}

export interface UpdateUserInput {
  readonly sessionToken: unknown;
  readonly name?: unknown;
  readonly image?: unknown;
}

const decodeVerificationToken = Schema.decodeUnknownEffect(VerificationToken);
const decodeSessionToken = Schema.decodeUnknownEffect(SessionToken);

const parseVerificationToken = (
  input: unknown,
): Effect.Effect<VerificationToken, BoundaryParseError> =>
  decodeVerificationToken(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(
      () => new BoundaryParseError({ field: "token", reason: "Invalid verification token" }),
    ),
  );

const parseSessionToken = (input: unknown): Effect.Effect<SessionToken, BoundaryParseError> =>
  decodeSessionToken(Redacted.isRedacted(input) ? Redacted.value(input) : input).pipe(
    Effect.mapError(
      () => new BoundaryParseError({ field: "sessionToken", reason: "Invalid session token" }),
    ),
  );

const parseOptionalClientIp = (
  boundary: typeof AuthBoundary.Service,
  input: unknown,
): Effect.Effect<ClientIp | undefined, BoundaryParseError> =>
  input === undefined ? Effect.sync(() => undefined) : boundary.parseClientIp(input);

const parseRequiredDisplayName = (input: unknown): Effect.Effect<string, BoundaryParseError> =>
  typeof input !== "string"
    ? Effect.fail(new BoundaryParseError({ field: "name", reason: "Expected string" }))
    : input.trim() === ""
      ? Effect.fail(new BoundaryParseError({ field: "name", reason: "Expected non-empty string" }))
      : Effect.succeed(input);

const parseOptionalDisplayName = (
  input: unknown,
): Effect.Effect<string | undefined, BoundaryParseError> =>
  input === undefined
    ? Effect.sync(() => undefined)
    : parseRequiredDisplayName(input).pipe(Effect.map((name) => name));

const parseOptionalProfileImage = (
  input: unknown,
): Effect.Effect<string | null | undefined, BoundaryParseError> =>
  input === undefined
    ? Effect.sync(() => undefined)
    : input === null
      ? Effect.succeed(null)
      : typeof input === "string"
        ? Effect.succeed(input)
        : Effect.fail(
            new BoundaryParseError({ field: "image", reason: "Expected string or null" }),
          );

const parseSignUpCommand = Effect.fn("Auth.parseSignUpCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: SignUpInput,
) {
  const email = yield* boundary.parseEmail(input.email);
  const password = yield* boundary.parsePassword(input.password);
  const name = yield* parseRequiredDisplayName(input.name);
  const verificationCallbackUrl = yield* boundary.parseCallbackUrl(input.verificationCallbackUrl);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    email,
    password,
    name,
    verificationCallbackUrl,
    ...(ip === undefined ? {} : { ip }),
  } satisfies SignUpCommand;
});

const parseSignInCommand = Effect.fn("Auth.parseSignInCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: SignInInput,
) {
  const email = yield* boundary.parseEmail(input.email);
  const password = yield* boundary.parsePassword(input.password);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    email,
    password,
    ...(ip === undefined ? {} : { ip }),
    ...(input.userAgent === undefined ? {} : { userAgent: input.userAgent }),
  } satisfies SignInCommand;
});

const parseVerifyEmailCommand = Effect.fn("Auth.parseVerifyEmailCommand")(function* (
  input: VerifyEmailInput,
) {
  const token = yield* parseVerificationToken(input.token);
  return { token } satisfies VerifyEmailCommand;
});

const parseRequestPasswordResetCommand = Effect.fn("Auth.parseRequestPasswordResetCommand")(
  function* (boundary: typeof AuthBoundary.Service, input: RequestPasswordResetInput) {
    const email = yield* boundary.parseEmail(input.email);
    const resetCallbackUrl = yield* boundary.parseCallbackUrl(input.resetCallbackUrl);
    const ip = yield* parseOptionalClientIp(boundary, input.ip);
    return {
      email,
      resetCallbackUrl,
      ...(ip === undefined ? {} : { ip }),
    } satisfies RequestPasswordResetCommand;
  },
);

const parseResetPasswordCommand = Effect.fn("Auth.parseResetPasswordCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: ResetPasswordInput,
) {
  const token = yield* parseVerificationToken(input.token);
  const password = yield* boundary.parsePassword(input.password);
  return { token, password } satisfies ResetPasswordCommand;
});

const parseChangePasswordCommand = Effect.fn("Auth.parseChangePasswordCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: ChangePasswordInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  const currentPassword = yield* boundary.parsePassword(input.currentPassword);
  const newPassword = yield* boundary.parsePassword(input.newPassword);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    sessionToken,
    currentPassword,
    newPassword,
    ...(ip === undefined ? {} : { ip }),
  } satisfies ChangePasswordCommand;
});

const parseDeleteUserCommand = Effect.fn("Auth.parseDeleteUserCommand")(function* (
  boundary: typeof AuthBoundary.Service,
  input: DeleteUserInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  const password = yield* boundary.parsePassword(input.password);
  const ip = yield* parseOptionalClientIp(boundary, input.ip);
  return {
    sessionToken,
    password,
    ...(ip === undefined ? {} : { ip }),
  };
});

const parseSessionTokenCommand = Effect.fn("Auth.parseSessionTokenCommand")(function* (
  input: SessionTokenInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  return { sessionToken } satisfies CurrentSessionCommand & ListSessionsInput & SignOutCommand;
});

const parseRevokeUserSessionCommand = Effect.fn("Auth.parseRevokeUserSessionCommand")(function* (
  input: RevokeUserSessionInput,
) {
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  return { sessionToken, sessionId: input.sessionId } satisfies RevokeUserSessionCommand;
});

const parseUpdateUserCommand = Effect.fn("Auth.parseUpdateUserCommand")(function* (
  input: UpdateUserInput,
) {
  if (Predicate.hasProperty(input, "email")) {
    return yield* new BoundaryParseError({
      field: "email",
      reason: "Email update is not supported",
    });
  }
  const sessionToken = yield* parseSessionToken(input.sessionToken);
  const name = yield* parseOptionalDisplayName(input.name);
  const image = yield* parseOptionalProfileImage(input.image);
  return {
    sessionToken,
    ...(name === undefined ? {} : { name }),
    ...(image === undefined ? {} : { image }),
  } satisfies UpdateUserCommand;
});

export interface AuthShape {
  readonly signUp: (
    input: SignUpInput,
  ) => Effect.Effect<
    SignUpResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailure
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly verifyEmail: (
    input: VerifyEmailInput,
  ) => Effect.Effect<
    VerifyEmailResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly resendVerification: (
    input: ResendVerificationInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | AuthStorageFailure
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly signIn: (
    input: SignInInput,
  ) => Effect.Effect<
    SignInResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordHashFailure
    | AuthStorageFailure
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
  readonly currentSession: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    SessionLookupResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly listSessions: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    ListSessionsResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeSession: (
    input: RevokeUserSessionInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeOtherSessions: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly revokeSessions: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly signOut: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    void,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly requestPasswordReset: (
    input: RequestPasswordResetInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | AuthStorageFailure
    | TokenGenerationFailure
    | AuthEmailFailure
    | RateLimitExceeded
  >;
  readonly resetPassword: (
    input: ResetPasswordInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailure
    | TokenGenerationFailure
  >;
  readonly changePassword: (
    input: ChangePasswordInput,
  ) => Effect.Effect<
    ChangePasswordResult,
    | PublicAuthError
    | BoundaryParseError
    | PasswordPolicyFailure
    | PasswordHashFailure
    | AuthStorageFailure
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
  readonly updateUser: (
    input: UpdateUserInput,
  ) => Effect.Effect<
    UpdateUserResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly listAccounts: (
    input: SessionTokenInput,
  ) => Effect.Effect<
    ListAccountsResult,
    PublicAuthError | BoundaryParseError | AuthStorageFailure | TokenGenerationFailure
  >;
  readonly deleteUser: (
    input: DeleteUserInput,
  ) => Effect.Effect<
    void,
    | PublicAuthError
    | BoundaryParseError
    | PasswordHashFailure
    | AuthStorageFailure
    | TokenGenerationFailure
    | RateLimitExceeded
  >;
}

export class Auth extends Context.Service<
  Auth,
  {
    readonly signUp: AuthShape["signUp"];
    readonly verifyEmail: AuthShape["verifyEmail"];
    readonly resendVerification: AuthShape["resendVerification"];
    readonly signIn: AuthShape["signIn"];
    readonly currentSession: AuthShape["currentSession"];
    readonly listSessions: AuthShape["listSessions"];
    readonly revokeSession: AuthShape["revokeSession"];
    readonly revokeOtherSessions: AuthShape["revokeOtherSessions"];
    readonly revokeSessions: AuthShape["revokeSessions"];
    readonly signOut: AuthShape["signOut"];
    readonly requestPasswordReset: AuthShape["requestPasswordReset"];
    readonly resetPassword: AuthShape["resetPassword"];
    readonly changePassword: AuthShape["changePassword"];
    readonly updateUser: AuthShape["updateUser"];
    readonly listAccounts: AuthShape["listAccounts"];
    readonly deleteUser: AuthShape["deleteUser"];
  }
>()("effect-auth/Auth") {}

const AuthLiveLayer = Layer.effect(Auth)(
  Effect.gen(function* () {
    const boundary = yield* AuthBoundary;
    const emailPassword = yield* EmailPasswordWorkflows;
    const sessions = yield* SessionWorkflows;
    const recovery = yield* PasswordRecoveryWorkflows;
    const identity = yield* IdentityWorkflows;

    return {
      signUp: (input) =>
        parseSignUpCommand(boundary, input).pipe(Effect.flatMap(emailPassword.signUp)),
      verifyEmail: (input) =>
        parseVerifyEmailCommand(input).pipe(Effect.flatMap(emailPassword.verifyEmail)),
      resendVerification: emailPassword.resendVerification,
      signIn: (input) =>
        parseSignInCommand(boundary, input).pipe(Effect.flatMap(emailPassword.signIn)),
      currentSession: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.currentSession)),
      listSessions: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.listSessions)),
      revokeSession: (input) =>
        parseRevokeUserSessionCommand(input).pipe(Effect.flatMap(sessions.revokeSession)),
      revokeOtherSessions: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.revokeOtherSessions)),
      revokeSessions: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.revokeSessions)),
      signOut: (input) => parseSessionTokenCommand(input).pipe(Effect.flatMap(sessions.signOut)),
      requestPasswordReset: (input) =>
        parseRequestPasswordResetCommand(boundary, input).pipe(
          Effect.flatMap(recovery.requestPasswordReset),
        ),
      resetPassword: (input) =>
        parseResetPasswordCommand(boundary, input).pipe(Effect.flatMap(recovery.resetPassword)),
      changePassword: (input) =>
        parseChangePasswordCommand(boundary, input).pipe(Effect.flatMap(recovery.changePassword)),
      updateUser: (input) =>
        parseUpdateUserCommand(input).pipe(Effect.flatMap(identity.updateUser)),
      listAccounts: (input) =>
        parseSessionTokenCommand(input).pipe(Effect.flatMap(identity.listAccounts)),
      deleteUser: (input) =>
        parseDeleteUserCommand(boundary, input).pipe(Effect.flatMap(identity.deleteUser)),
    };
  }),
);

const AuthStaticDefaultsLive = Layer.mergeAll(
  AuthBoundaryLive,
  SecureDefaultPasswordPolicy,
  NativeScryptPasswordHasher,
  AuthTokenLive,
);

const SessionPolicyFromAuthLiveConfig = Layer.effect(SessionPolicy)(
  Effect.gen(function* () {
    const config = yield* AuthLiveConfig;
    return {
      sessionTtlMillis: config.session.ttlMillis,
      sessionUpdateAgeMillis: config.session.updateAgeMillis,
    };
  }),
);

const VerificationTokenConfigFromAuthLiveConfig = Layer.effect(VerificationTokenConfig)(
  Effect.gen(function* () {
    const config = yield* AuthLiveConfig;
    return {
      emailVerificationTtlMillis: config.verification.emailVerificationTtlMillis,
      passwordResetTtlMillis: config.verification.passwordResetTtlMillis,
    };
  }),
);

const WorkflowServicesLive = Layer.mergeAll(
  EmailPasswordWorkflowsLive,
  SessionWorkflowsLive,
  PasswordRecoveryWorkflowsLive,
  IdentityWorkflowsLive,
);

const AuthDefaultsFromConfigLive = Layer.mergeAll(
  AuthStaticDefaultsLive,
  SessionPolicyFromAuthLiveConfig,
  VerificationTokenConfigFromAuthLiveConfig,
);

const AuthServicesFromConfigLive = WorkflowServicesLive.pipe(
  Layer.provideMerge(AuthDefaultsFromConfigLive),
);

const AuthLayerFromConfigLive = AuthLiveLayer.pipe(Layer.provide(AuthServicesFromConfigLive));

export const AuthLive = (
  config?: AuthLiveConfigInput,
): Layer.Layer<Auth | AuthLiveConfig, BoundaryParseError, AuthStorage | AuthEmail | RateLimiter> =>
  AuthLayerFromConfigLive.pipe(Layer.provideMerge(AuthLiveConfig.layer(config)));
