# Security policy

Only the latest commit on the default branch is supported.

Report vulnerabilities privately through this repository's GitHub Security
Advisory page. Do not open a public issue containing exploitable details,
credentials, secret material, private topology, account identifiers, or
generated production manifests.

Useful reports include public exposure of a private route, a mutable or
substitutable deployment input, a workload escaping restricted Pod Security,
an unintended network flow, a secret value in Git, excessive workload
identity, or a backup/restore path that fails to revoke restored sessions.

If any credential reaches Git history, logs, workflow artifacts, or rendered
output, treat it as compromised and rotate it immediately. Deleting it or
rewriting history is not remediation.
