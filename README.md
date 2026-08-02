# rs-cloud

Public, reference-only Kubernetes desired state for the RS Platform cloud
plane. Argo CD pulls this repository; CI only renders and validates it and has
no cloud, Kubernetes, or secret-store identity.

This baseline implements ADR-0037's production authentication vertical slice:
External Secrets Operator, cert-manager, Traefik, cloudflared,
CloudNativePG, a single-primary PostgreSQL cluster, and the two-listener
`rs-console` deployment.

## Boundaries

This repository owns raw Kubernetes resources, Argo CD applications, route
inventories, and policy tests. It never contains Terraform, application
source, container images, credentials, secret values or ciphertext, private
topology, account IDs, role ARNs, tunnel IDs, or mutable image tags.

`rs-infra` creates infrastructure, workload IAM roles, Parameter Store
entries, KMS keys, encrypted S3 storage, and the private network path.
`rs-console` publishes the application image and defines the matching API
contract.

## Layout and reconciliation

- `argocd/bootstrap/application.yaml` is the one operator-applied root.
- `argocd/apps` creates ordered Argo CD applications for namespaces,
  platform dependencies, and services.
- `namespaces` applies restricted Pod Security labels and default-deny
  ingress and egress.
- `platform` installs operators and the public tunnel boundary.
- `services/console` owns PostgreSQL, console, migrations, routes, and
  workload NetworkPolicies.
- `policy` contains Conftest rules and positive/negative fixtures.

The useful Kustomize roots are:

```sh
kustomize build argocd/apps
kustomize build namespaces
kustomize build platform
kustomize build services
```

Sync waves establish namespaces first, operators second, and services last.
Automated sync is deliberately absent. ADR-0036/0038 promotion gates must be
completed before the root application is enabled.

## Authentication surface

Both route sets use `platform-api.ricardosaad.com`, but they terminate on
different Traefik entrypoints and Kubernetes Services. There is no `/api`
prefix. The public tunnel can reach only `traefik-public`, whose inventory
contains:

- `/health/live` and `/health/ready`
- `/v1/capabilities`
- `/v1/session`
- `/v1/auth/login/start` and `/v1/auth/login/finish`
- `/v1/auth/logout`
- `/v1/auth/setup/start` and `/v1/auth/setup/finish`
- `/v1/recovery/request`

Those public paths terminate on `rs-console-public:8080`.

The private route binds only to `traefik-private`. Because split-horizon DNS
sends the same hostname privately, it must also expose the public
auth/session/capability/setup/recovery-request paths (again to
`rs-console-public:8080`) plus the operator surface on
`rs-console-private:8081`:

- `/v1/operator/bootstrap/start` and `/v1/operator/bootstrap/finish`
- `/v1/operator/recoveries` and `/v1/operator/recoveries/{id}/approve|setup`
  (`PathPrefix`)
- `/v1/operator/capabilities`

Conftest rejects a `/v1/operator/` path on any non-private surface.
NetworkPolicies permit cloudflared to reach only Traefik's public port,
Traefik to reach the two explicit console listener ports, and
console/migrations to reach PostgreSQL.

## PostgreSQL recovery posture

The CloudNativePG `Cluster` has exactly one instance. It uses encrypted gp3,
archives WAL continuously, and takes a scheduled base backup to encrypted S3
using service-account federation. It is recoverable, not highly available.
Promotion requires a restore drill that increments the authentication epoch
and proves restored sessions, ceremonies, setup capabilities, and recovery
capabilities are rejected.

CloudNativePG v1.30.0 is referenced by its released manifest and verified
against SHA-256
`f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88`.

## Required promotion substitutions

The checked-in state intentionally cannot be promoted:

- replace the all-zero `rs-console` image digest with a released, signed
  digest;
- replace `REPLACE_AT_PROMOTION_ESO_ROLE_ARN` and
  `REPLACE_AT_PROMOTION_POSTGRES_BACKUP_ROLE_ARN` with reviewed workload role
  annotations;
- replace `REPLACE_AT_PROMOTION_BACKUP_BUCKET` with the encrypted bucket
  name and `REPLACE_AT_PROMOTION_ACME_EMAIL` with the certificate contact;
- replace the documentation-only `192.0.2.0/24` private-ingress CIDR with the
  reviewed Role 4 gateway source range;
- create Parameter Store values referenced under `/cluster/` for the tunnel,
  database owner, and DNS solver;
- verify exact Helm chart releases and the CloudNativePG checksum during
  dependency updates.

`policy/promotion.rego` rejects every marker above. Placeholder replacement
must happen in reviewed Git desired state; no CI secret-rendering path exists.

## Validation

Install `kustomize`, `kubectl`, `yamllint`, `conftest`, `kubeconform`,
`actionlint`, `gitleaks`, and `trivy`, then run:

```sh
./scripts/validate.sh
```

The script renders every root, checks YAML, validates Kubernetes 1.34 schemas,
runs policy and fixtures, verifies the CloudNativePG release checksum, and
proves the current tree remains promotion-blocked. CI runs the same static
checks with no credentials.
