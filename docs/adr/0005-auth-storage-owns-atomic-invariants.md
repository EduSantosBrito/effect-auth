# Auth Storage Owns Atomic Invariants

Effect Auth keeps multi-step auth invariants inside **Auth Storage** instead of exposing only primitive persistence calls to core workflows or end-user code. Packaged **Storage Adapters** implement behavioral operations such as password reset completion, password change, user deletion, session revocation, and session rotation transactionally, because partial commits across token consumption, password updates, deleted identities, and session changes would weaken the security model.
