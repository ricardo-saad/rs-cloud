#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

required=(kustomize yamllint conftest kubeconform)
for tool in "${required[@]}"; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "missing required validation tool: ${tool}" >&2
    exit 1
  fi
done

cd "${root}"

yamllint -c .yamllint.yaml \
  .github argocd namespaces platform services policy

roots=(argocd/apps namespaces platform services)
for kustomize_root in "${roots[@]}"; do
  output="${tmp}/${kustomize_root//\//-}.yaml"
  kustomize build "${kustomize_root}" >"${output}"
  test -s "${output}"
done

kubeconform \
  -ignore-missing-schemas \
  -kubernetes-version 1.34.0 \
  -schema-location default \
  -strict \
  -summary \
  "${tmp}"/*.yaml

conftest test --policy policy/baseline "${tmp}"/*.yaml
conftest test --policy policy/baseline policy/fixtures/allow
conftest test --policy policy/baseline policy/fixtures/flows

for fixture in policy/fixtures/deny/*.yaml; do
  if conftest test --policy policy/baseline "${fixture}" >/dev/null 2>&1; then
    echo "negative fixture unexpectedly passed: ${fixture}" >&2
    exit 1
  fi
done

if conftest test --policy policy/promotion \
  "${tmp}/platform.yaml" "${tmp}/services.yaml" >/dev/null 2>&1; then
  echo "desired state unexpectedly passed promotion policy" >&2
  exit 1
fi

python3 - <<'PY'
import pathlib
import re

invalid = []
external = re.compile(r"^[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$")
for path in sorted(pathlib.Path(".github/workflows").glob("*.yml")):
    for number, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if not stripped.startswith("uses:"):
            continue
        value = stripped.removeprefix("uses:").strip()
        if not external.fullmatch(value):
            invalid.append(f"{path}:{number}:{value}")

if invalid:
    raise SystemExit(
        "GitHub Actions must use full commit SHAs:\n" + "\n".join(invalid)
    )

workflow = "\n".join(
    path.read_text()
    for path in pathlib.Path(".github/workflows").glob("*.yml")
)
for forbidden in (
    "id-token: write",
    "aws-actions/configure-aws-credentials",
    "pull_request_target",
):
    if forbidden in workflow:
        raise SystemExit(f"forbidden CI identity/deployment construct: {forbidden}")
PY

if [[ "${VERIFY_UPSTREAM:-1}" == "1" ]]; then
  expected="f8bede43fe4ee0d478c2355b204a36876b2ae4faac60f2a9452280b293da3b88"
  actual="$(
    curl --fail --silent --show-error --location \
      "https://github.com/cloudnative-pg/cloudnative-pg/releases/download/v1.30.0/cnpg-1.30.0.yaml" |
      shasum -a 256 |
      awk '{print $1}'
  )"
  test "${actual}" = "${expected}"
fi

echo "All static validation passed; promotion remains fail-closed."
