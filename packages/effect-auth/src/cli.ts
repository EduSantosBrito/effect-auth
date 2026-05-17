#!/usr/bin/env node
import { Console, Effect, FileSystem, Layer, Path, Queue, Schema, Stdio, Terminal } from "effect";
import { CliError, Command, Flag } from "effect/unstable/cli";
import * as ChildProcessSpawner from "effect/unstable/process/ChildProcessSpawner";
import {
  defaultDrizzlePgSchemaOutput,
  defaultDrizzlePgSchemaPrefix,
  generateDrizzlePgSchemaFile,
} from "./cli/generate.js";

const packageVersion = "0.3.0";

class CliFailure extends Schema.TaggedErrorClass<CliFailure>()("CliFailure", {
  reason: Schema.String,
}) {}

const unavailableChildProcessSpawner = ChildProcessSpawner.make(() => Effect.never);

const terminal = Terminal.make({
  columns: Effect.succeed(80),
  readInput: Queue.unbounded<Terminal.UserInput>(),
  readLine: Effect.fail(new Terminal.QuitError()),
  display: (text) => Console.log(text),
});

const cliEnvironment = (args: ReadonlyArray<string>) =>
  Layer.mergeAll(
    FileSystem.layerNoop({}),
    Path.layer,
    Stdio.layerTest({ args: Effect.succeed(args) }),
    Layer.succeed(Terminal.Terminal)(terminal),
    Layer.succeed(ChildProcessSpawner.ChildProcessSpawner)(unavailableChildProcessSpawner),
  );

const loadNodeModules = Effect.fn("loadNodeModules")(function* () {
  const fs = yield* Effect.tryPromise({
    // @effect-diagnostics-next-line nodeBuiltinImport:off - The CLI writes generated schema files using Node fs.
    try: () => import("node:fs/promises"),
    catch: () => new CliFailure({ reason: "Unable to load fs module" }),
  });
  const path = yield* Effect.tryPromise({
    // @effect-diagnostics-next-line nodeBuiltinImport:off - The CLI resolves output paths using Node path.
    try: () => import("node:path"),
    catch: () => new CliFailure({ reason: "Unable to load path module" }),
  });
  return { fs, path };
});

const fileExists = (
  fs: typeof import("node:fs/promises"),
  filePath: string,
): Effect.Effect<boolean> =>
  Effect.promise(() =>
    fs.access(filePath).then(
      () => true,
      () => false,
    ),
  );

const writeGeneratedSchema = Effect.fn("writeGeneratedSchema")(function* (input: {
  readonly output: string;
  readonly prefix: string;
  readonly force: boolean;
  readonly cwd: string;
}) {
  const { fs, path } = yield* loadNodeModules();
  const absoluteOutput = path.resolve(input.cwd, input.output);
  const exists = yield* fileExists(fs, absoluteOutput);
  if (exists && !input.force) {
    return yield* new CliFailure({
      reason: `Refusing to overwrite ${input.output}. Pass --force to overwrite it.`,
    });
  }

  yield* Effect.tryPromise({
    try: () => fs.mkdir(path.dirname(absoluteOutput), { recursive: true }),
    catch: () => new CliFailure({ reason: "Unable to create output directory" }),
  });
  yield* Effect.tryPromise({
    try: () => fs.writeFile(absoluteOutput, generateDrizzlePgSchemaFile({ prefix: input.prefix })),
    catch: () => new CliFailure({ reason: "Unable to write schema file" }),
  });
  return absoluteOutput;
});

export const makeCli = (cwd: string) => {
  const generate = Command.make(
    "generate",
    {
      output: Flag.string("output").pipe(
        Flag.withAlias("o"),
        Flag.withMetavar("path"),
        Flag.withDescription("Output TypeScript schema file"),
        Flag.withDefault(defaultDrizzlePgSchemaOutput),
      ),
      prefix: Flag.string("prefix").pipe(
        Flag.withMetavar("value"),
        Flag.withDescription("Table prefix for generated Drizzle Postgres tables"),
        Flag.withDefault(defaultDrizzlePgSchemaPrefix),
      ),
      force: Flag.boolean("force").pipe(
        Flag.withAlias("f"),
        Flag.withDescription("Overwrite an existing output file"),
      ),
      dryRun: Flag.boolean("dry-run").pipe(
        Flag.withDescription("Print generated schema instead of writing it"),
      ),
    },
    (config) =>
      config.dryRun
        ? Console.log(generateDrizzlePgSchemaFile({ prefix: config.prefix }))
        : writeGeneratedSchema({ ...config, cwd }).pipe(
            Effect.flatMap((output) => Console.log(`Generated Drizzle Postgres schema: ${output}`)),
          ),
  ).pipe(
    Command.withDescription("Generate a Drizzle Postgres auth schema TypeScript file"),
    Command.withExamples([
      {
        command: "effect-auth generate",
        description: `Generate ${defaultDrizzlePgSchemaOutput}`,
      },
      {
        command: "effect-auth generate --output src/db/auth-schema.ts --prefix auth_ --force",
        description: "Generate a schema file at a custom path",
      },
    ]),
  );

  return Command.make("effect-auth", {}, () =>
    Console.log("Run effect-auth --help for usage."),
  ).pipe(
    Command.withDescription("effect-auth command line tools"),
    Command.withSubcommands([generate]),
  );
};

export const runCli = (
  args: ReadonlyArray<string>,
  cwd: string,
): Effect.Effect<void, CliFailure | CliError.CliError> =>
  Command.runWith(makeCli(cwd), { version: packageVersion })(args).pipe(
    Effect.provide(cliEnvironment(args)),
  );

const setExitCode = Effect.sync(() => {
  process.exitCode = 1;
});

const program = runCli(process.argv.slice(2), process.cwd()).pipe(
  Effect.catchTag("CliFailure", (error) =>
    Console.error(error.reason).pipe(Effect.andThen(setExitCode)),
  ),
  Effect.catch(() => setExitCode),
);

Effect.runPromise(program);
