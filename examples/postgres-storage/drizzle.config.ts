export default {
  dialect: "postgresql",
  schema: "./src/schema.ts",
  out: "./drizzle",
  dbCredentials: {
    url:
      process.env.DATABASE_URL ??
      "postgres://effect_auth:effect_auth@localhost:5432/effect_auth_example",
  },
};
