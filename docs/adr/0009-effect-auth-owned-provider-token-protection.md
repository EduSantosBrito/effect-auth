# Effect Auth-Owned Provider Token Protection

Provider tokens returned by External Providers are protected by Effect Auth before they reach **Auth Storage**, through an application-replaceable Effect service rather than storage-adapter-specific hooks or raw token persistence. This deliberately differs from Better Auth's hook-based token encryption model because secure-by-default provider token handling and consistent adapter behavior are more important than making plaintext storage the easiest path.
