import { definePlugin, defineRule } from "@oxlint/plugins";

type Node = {
  readonly type?: string;
  readonly name?: string;
  readonly value?: unknown;
  readonly operator?: string;
  readonly object?: unknown;
  readonly property?: unknown;
  readonly callee?: unknown;
  readonly arguments?: ReadonlyArray<unknown>;
  readonly key?: unknown;
  readonly source?: unknown;
  readonly specifiers?: ReadonlyArray<unknown>;
  readonly left?: unknown;
  readonly right?: unknown;
  readonly consequent?: unknown;
  readonly alternate?: unknown;
  readonly body?: unknown;
  readonly expression?: unknown;
  readonly typeAnnotation?: unknown;
  readonly typeArguments?: unknown;
  readonly typeParameters?: unknown;
  readonly parent?: unknown;
  readonly properties?: ReadonlyArray<unknown>;
};

const asNode = (value: unknown): Node | undefined =>
  typeof value === "object" && value !== null && "type" in value ? value : undefined;

const isIdentifier = (value: unknown, name?: string): boolean => {
  const node = asNode(value);
  return (
    node?.type === "Identifier" &&
    typeof node.name === "string" &&
    (name === undefined || node.name === name)
  );
};

const propertyName = (value: unknown): string | undefined => {
  const node = asNode(value);
  if (node?.type === "Identifier" && typeof node.name === "string") return node.name;
  if (node?.type === "PrivateIdentifier" && typeof node.name === "string") return node.name;
  if (node?.type === "Literal" && typeof node.value === "string") return node.value;
  return undefined;
};

const literalValue = (value: unknown): unknown => asNode(value)?.value;

const isMember = (value: unknown, objectName: string, memberName: string): boolean => {
  const node = asNode(value);
  return (
    node?.type === "MemberExpression" &&
    isIdentifier(node.object, objectName) &&
    propertyName(node.property) === memberName
  );
};

const isEffectMember = (value: unknown, memberName: string): boolean =>
  isMember(value, "Effect", memberName);

const isEffectVoid = (value: unknown): boolean =>
  isEffectMember(value, "void") || isEffectMember(value, "unit");

const isVoidReturningFunction = (value: unknown): boolean => {
  const node = asNode(value);
  if (node?.type !== "ArrowFunctionExpression" && node?.type !== "FunctionExpression") return false;
  if (isEffectVoid(node.body)) return true;

  const body = asNode(node.body);
  if (body?.type !== "BlockStatement" || !Array.isArray(body.body) || body.body.length !== 1) {
    return false;
  }

  const statement = asNode(body.body[0]);
  return statement?.type === "ReturnStatement" && isEffectVoid(statement.argument);
};

const isNullCheck = (value: unknown): Node | undefined => {
  const node = asNode(value);
  return node?.type === "BinaryExpression" && (node.operator === "!==" || node.operator === "!=")
    ? node
    : undefined;
};

const sameExpression = (left: unknown, right: unknown): boolean => {
  const leftNode = asNode(left);
  const rightNode = asNode(right);
  if (leftNode?.type === "Identifier" && rightNode?.type === "Identifier") {
    return leftNode.name === rightNode.name;
  }
  return left === right;
};

const checkedNullTarget = (value: unknown): unknown => {
  const node = isNullCheck(value);
  if (node === undefined) return undefined;
  if (literalValue(node.right) === null) return node.left;
  if (literalValue(node.left) === null) return node.right;
  return undefined;
};

const isOptionSomeCall = (value: unknown, target: unknown): boolean => {
  const node = asNode(value);
  return (
    node?.type === "CallExpression" &&
    isMember(node.callee, "Option", "some") &&
    Array.isArray(node.arguments) &&
    node.arguments.length === 1 &&
    sameExpression(node.arguments[0], target)
  );
};

const isOptionNoneCall = (value: unknown): boolean => {
  const node = asNode(value);
  return node?.type === "CallExpression" && isMember(node.callee, "Option", "none");
};

const noExplicitAny = defineRule({
  meta: { type: "problem", docs: { description: "Disallow explicit any." } },
  createOnce(context) {
    const report = (node: unknown) => {
      context.report({
        node,
        message: "Do not use any. Use unknown, generics, or a precise type.",
      });
    };

    return {
      TSAnyKeyword: report,
    };
  },
});

const noTypeCasting = defineRule({
  meta: { type: "problem", docs: { description: "Disallow TypeScript type assertions." } },
  createOnce(context) {
    const report = (node: unknown) => {
      context.report({
        node,
        message:
          "Do not cast with type assertions. Parse at boundaries or model the type precisely.",
      });
    };

    return {
      TSAsExpression: report,
      TSTypeAssertion: report,
    };
  },
});

const noNonNullAssertion = defineRule({
  meta: { type: "problem", docs: { description: "Disallow non-null assertions." } },
  createOnce(context) {
    return {
      TSNonNullExpression(node) {
        context.report({
          node,
          message:
            "Do not use non-null assertions. Represent absence with Option or validate first.",
        });
      },
    };
  },
});

const noDisableValidation = defineRule({
  meta: { type: "problem", docs: { description: "Disallow disableValidation: true." } },
  createOnce(context) {
    return {
      Property(node) {
        if (propertyName(node.key) === "disableValidation" && literalValue(node.value) === true) {
          context.report({
            node,
            message: "Do not use disableValidation: true. Fix the schema or input.",
          });
        }
      },
    };
  },
});

const noSqlTypeParameter = defineRule({
  meta: { type: "problem", docs: { description: "Disallow sql<Type>`...`." } },
  createOnce(context) {
    return {
      TaggedTemplateExpression(node) {
        if (
          (node.typeArguments === undefined && node.typeParameters === undefined) ||
          !isIdentifier(node.tag, "sql")
        ) {
          return;
        }
        context.report({
          node,
          message:
            "Do not use sql<Type>`...`. Use Schema-backed SQL decoding for runtime validation.",
        });
      },
    };
  },
});

const preferOptionFromNullable = defineRule({
  meta: { type: "suggestion", docs: { description: "Prefer Option.fromNullable." } },
  createOnce(context) {
    return {
      ConditionalExpression(node) {
        const target = checkedNullTarget(node.test);
        if (target === undefined) return;

        if (isOptionSomeCall(node.consequent, target) && isOptionNoneCall(node.alternate)) {
          context.report({
            node,
            message: "Use Option.fromNullable(...) instead of Option.some/none ternary.",
          });
        }
      },
    };
  },
});

const noEffectIgnore = defineRule({
  meta: { type: "problem", docs: { description: "Disallow Effect.ignore." } },
  createOnce(context) {
    return {
      MemberExpression(node) {
        if (isEffectMember(node, "ignore")) {
          context.report({
            node,
            message: "Do not use Effect.ignore. Handle or propagate errors explicitly.",
          });
        }
      },
    };
  },
});

const noEffectCatchAllCause = defineRule({
  meta: { type: "problem", docs: { description: "Disallow Effect.catchAllCause." } },
  createOnce(context) {
    return {
      MemberExpression(node) {
        if (isEffectMember(node, "catchAllCause")) {
          context.report({
            node,
            message:
              "Do not use Effect.catchAllCause for recoverable errors. Catch expected errors only.",
          });
        }
      },
    };
  },
});

const noSilentErrorSwallow = defineRule({
  meta: {
    type: "problem",
    docs: { description: "Disallow catch handlers returning Effect.void." },
  },
  createOnce(context) {
    return {
      CallExpression(node) {
        const catchName = propertyName(asNode(node.callee)?.property);
        if (!isIdentifier(asNode(node.callee)?.object, "Effect")) return;

        if (
          catchName === "catchAll" &&
          Array.isArray(node.arguments) &&
          isVoidReturningFunction(node.arguments[0])
        ) {
          context.report({
            node: node.arguments[0],
            message: "Do not swallow errors with Effect.void.",
          });
        }

        if (
          catchName === "catchTag" &&
          Array.isArray(node.arguments) &&
          isVoidReturningFunction(node.arguments[1])
        ) {
          context.report({
            node: node.arguments[1],
            message: "Do not swallow errors with Effect.void.",
          });
        }

        if (catchName !== "catchTags" || !Array.isArray(node.arguments)) return;
        const handlers = asNode(node.arguments[0]);
        if (handlers?.type !== "ObjectExpression" || !Array.isArray(handlers.properties)) return;

        for (const property of handlers.properties) {
          const handler = asNode(property)?.value;
          if (isVoidReturningFunction(handler)) {
            context.report({ node: handler, message: "Do not swallow errors with Effect.void." });
          }
        }
      },
    };
  },
});

const noServiceOption = defineRule({
  meta: { type: "problem", docs: { description: "Disallow Effect.serviceOption." } },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (isEffectMember(node.callee, "serviceOption")) {
          context.report({
            node,
            message: "Do not use Effect.serviceOption. Require services in context.",
          });
        }
      },
    };
  },
});

const isLayerProvideCall = (value: unknown): boolean => {
  const node = asNode(value);
  return node?.type === "CallExpression" && isMember(node.callee, "Layer", "provide");
};

const noNestedLayerProvide = defineRule({
  meta: { type: "problem", docs: { description: "Disallow nested Layer.provide." } },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (!isLayerProvideCall(node) || !Array.isArray(node.arguments)) return;
        for (const argument of node.arguments) {
          if (isLayerProvideCall(argument)) {
            context.report({
              node: argument,
              message: "Avoid nested Layer.provide. Extract it or use Layer.provideMerge.",
            });
          }
        }
      },
    };
  },
});

const noVoidExpression = defineRule({
  meta: { type: "problem", docs: { description: "Disallow void expressions." } },
  createOnce(context) {
    return {
      UnaryExpression(node) {
        if (node.operator === "void") {
          context.report({
            node,
            message: "Do not use void expressions. Handle or intentionally discard another way.",
          });
        }
      },
    };
  },
});

const noDirectFetch = defineRule({
  meta: { type: "problem", docs: { description: "Disallow direct fetch." } },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (
          isIdentifier(node.callee, "fetch") ||
          isMember(node.callee, "window", "fetch") ||
          isMember(node.callee, "globalThis", "fetch")
        ) {
          context.report({
            node,
            message: "Do not call fetch directly. Use a typed Effect HTTP/client boundary.",
          });
        }
      },
    };
  },
});

const noLocalStorage = defineRule({
  meta: { type: "problem", docs: { description: "Disallow localStorage." } },
  createOnce(context) {
    return {
      Identifier(node) {
        if (node.name === "localStorage") {
          context.report({ node, message: "Do not use localStorage for auth state or secrets." });
        }
      },
    };
  },
});

const noManualLayerBuildInTests = defineRule({
  meta: { type: "problem", docs: { description: "Disallow Layer.build in tests." } },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (isMember(node.callee, "Layer", "build")) {
          context.report({
            node,
            message:
              "Avoid manual Layer.build in tests. Prefer it.layer(...) or Effect.provide(layer).",
          });
        }
      },
    };
  },
});

const preferEffectVitest = defineRule({
  meta: { type: "suggestion", docs: { description: "Prefer it.effect for Effect tests." } },
  createOnce(context) {
    return {
      CallExpression(node) {
        if (!isIdentifier(node.callee, "test") && !isIdentifier(node.callee, "it")) return;
        if (!Array.isArray(node.arguments)) return;
        const body = asNode(node.arguments[1]);
        if (body?.type === "ArrowFunctionExpression" || body?.type === "FunctionExpression") {
          context.report({ node: node.callee, message: "Prefer it.effect(...) for Effect tests." });
        }
      },
    };
  },
});

const preferEffectVitestAssert = defineRule({
  meta: { type: "suggestion", docs: { description: "Prefer assert from @effect/vitest." } },
  createOnce(context) {
    return {
      ImportDeclaration(node) {
        if (literalValue(node.source) !== "@effect/vitest" || !Array.isArray(node.specifiers))
          return;
        for (const specifier of node.specifiers) {
          const imported = propertyName(asNode(specifier)?.imported);
          if (imported === "expect") {
            context.report({
              node: specifier,
              message: "Prefer assert from @effect/vitest over expect.",
            });
          }
        }
      },
    };
  },
});

export default definePlugin({
  meta: { name: "effect-auth" },
  rules: {
    "no-explicit-any": noExplicitAny,
    "no-type-casting": noTypeCasting,
    "no-non-null-assertion": noNonNullAssertion,
    "no-disable-validation": noDisableValidation,
    "no-sql-type-parameter": noSqlTypeParameter,
    "prefer-option-from-nullable": preferOptionFromNullable,
    "no-effect-ignore": noEffectIgnore,
    "no-effect-catchallcause": noEffectCatchAllCause,
    "no-silent-error-swallow": noSilentErrorSwallow,
    "no-service-option": noServiceOption,
    "no-nested-layer-provide": noNestedLayerProvide,
    "no-void-expression": noVoidExpression,
    "no-direct-fetch": noDirectFetch,
    "no-localstorage": noLocalStorage,
    "no-manual-layer-build-in-tests": noManualLayerBuildInTests,
    "prefer-effect-vitest": preferEffectVitest,
    "prefer-effect-vitest-assert": preferEffectVitestAssert,
  },
});
