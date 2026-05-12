# Compliance User Deletion Deletes Auth Records

Effect Auth treats **User Deletion** as compliance-driven hard deletion of the User and dependent auth records, even though revoked Sessions and consumed Verification Tokens otherwise remain history data. Storage Adapters should delete Accounts, Sessions, and user-scoped Verification Tokens with the User because GDPR/LGPD-style deletion rights are more important than preserving default auth audit history without an explicit retention policy.
