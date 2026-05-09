# Native Scrypt Password Hashing

Email/password v1 uses a runtime-native Scrypt **Password Hasher** by default, exposed as an Effect service, and does not ship a JavaScript hashing fallback. The initial preset is `N=16384`, `r=16`, `p=1`, `dkLen=64`, stored in a PHC-like **Password Hash** string with the salt and derived key for future upgrades. This favours memory-hard password storage and event-loop safety over universal runtime portability; runtimes without built-in Scrypt must provide their own **Password Hasher** or disable email/password.
