package main

import rego.v1

workload_kinds := {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
managed_namespaces := {"ingress-system", "rs-console"}
allowed_flows := {
  {"source": "cloudflared", "destination": "traefik-public", "port": 8000},
  {"source": "traefik", "destination": "rs-console-public", "port": 8080},
  {"source": "traefik", "destination": "rs-console-private", "port": 8081},
  {"source": "rs-console", "destination": "postgres", "port": 5432},
  {"source": "rs-console-migrate", "destination": "postgres", "port": 5432},
  {"source": "postgres", "destination": "s3", "port": 443},
}

is_workload if input.kind in workload_kinds

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"
pod_spec := input.spec.template.spec if input.kind != "CronJob"

containers contains container if {
  is_workload
  some container in pod_spec.containers
}

deny contains "Secret manifests are forbidden; use ExternalSecret" if {
  input.kind == "Secret"
}

deny contains msg if {
  some container in containers
  not regex.match(`^[^[:space:]@]+@sha256:[0-9a-f]{64}$`, container.image)
  msg := sprintf("%s/%s container %s must use an immutable sha256 digest", [
    input.kind,
    input.metadata.name,
    container.name,
  ])
}

deny contains msg if {
  input.kind == "Cluster"
  input.apiVersion == "postgresql.cnpg.io/v1"
  not regex.match(`^[^[:space:]@]+:[^[:space:]@]+@sha256:[0-9a-f]{64}$`, input.spec.imageName)
  msg := sprintf("Cluster/%s imageName must include an immutable tag and digest", [input.metadata.name])
}

deny contains msg if {
  some container in containers
  request := object.get(object.get(container, "resources", {}), "requests", {})
  not object.get(request, "cpu", false)
  msg := sprintf("%s/%s container %s lacks a CPU request", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  some container in containers
  request := object.get(object.get(container, "resources", {}), "requests", {})
  not object.get(request, "memory", false)
  msg := sprintf("%s/%s container %s lacks a memory request", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  some container in containers
  limit := object.get(object.get(container, "resources", {}), "limits", {})
  not object.get(limit, "cpu", false)
  msg := sprintf("%s/%s container %s lacks a CPU limit", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  some container in containers
  limit := object.get(object.get(container, "resources", {}), "limits", {})
  not object.get(limit, "memory", false)
  msg := sprintf("%s/%s container %s lacks a memory limit", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  is_workload
  object.get(object.get(pod_spec, "securityContext", {}), "runAsNonRoot", false) != true
  msg := sprintf("%s/%s must set pod runAsNonRoot", [input.kind, input.metadata.name])
}

deny contains msg if {
  is_workload
  object.get(object.get(object.get(pod_spec, "securityContext", {}), "seccompProfile", {}), "type", "") != "RuntimeDefault"
  msg := sprintf("%s/%s must use RuntimeDefault seccomp", [input.kind, input.metadata.name])
}

deny contains msg if {
  some container in containers
  context := object.get(container, "securityContext", {})
  object.get(context, "allowPrivilegeEscalation", true) != false
  msg := sprintf("%s/%s container %s permits privilege escalation", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  some container in containers
  context := object.get(container, "securityContext", {})
  object.get(context, "privileged", false) == true
  msg := sprintf("%s/%s container %s is privileged", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  some container in containers
  context := object.get(container, "securityContext", {})
  object.get(context, "readOnlyRootFilesystem", false) != true
  msg := sprintf("%s/%s container %s must use a read-only root filesystem", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  some container in containers
  drops := object.get(object.get(object.get(container, "securityContext", {}), "capabilities", {}), "drop", [])
  not "ALL" in drops
  msg := sprintf("%s/%s container %s must drop ALL capabilities", [input.kind, input.metadata.name, container.name])
}

deny contains msg if {
  is_workload
  input.metadata.namespace in managed_namespaces
  object.get(object.get(input.metadata, "annotations", {}), "rs.io/network-policy", "") != "enforced"
  msg := sprintf("%s/%s must declare its NetworkPolicy contract", [input.kind, input.metadata.name])
}

deny contains msg if {
  input.kind == "Namespace"
  labels := object.get(input.metadata, "labels", {})
  object.get(labels, "pod-security.kubernetes.io/enforce", "") != "restricted"
  msg := sprintf("Namespace/%s must enforce restricted Pod Security", [input.metadata.name])
}

deny contains msg if {
  input.kind == "Namespace"
  annotations := object.get(input.metadata, "annotations", {})
  object.get(annotations, "rs.io/default-deny", "") != "enforced"
  msg := sprintf("Namespace/%s lacks the default-deny contract", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.name == "default-deny"
  object.get(input.spec, "podSelector", null) != {}
  msg := sprintf("NetworkPolicy/%s default deny must select every pod", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.name == "default-deny"
  not "Ingress" in input.spec.policyTypes
  msg := sprintf("NetworkPolicy/%s must deny ingress", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkPolicy"
  input.metadata.name == "default-deny"
  not "Egress" in input.spec.policyTypes
  msg := sprintf("NetworkPolicy/%s must deny egress", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ExternalSecret"
  annotation := object.get(object.get(input.metadata, "annotations", {}), "rs.io/reload-contract", "")
  annotation == ""
  msg := sprintf("ExternalSecret/%s must declare a reload contract", [input.metadata.name])
}

deny contains msg if {
  input.kind == "ExternalSecret"
  some item in input.spec.data
  not startswith(item.remoteRef.key, "/cluster/")
  msg := sprintf("ExternalSecret/%s references a key outside /cluster/", [input.metadata.name])
}

deny contains msg if {
  input.kind == "IngressRoute"
  surface := object.get(object.get(input.metadata, "annotations", {}), "rs.io/surface", "")
  not surface in {"public-human", "public-machine", "private-operator"}
  msg := sprintf("IngressRoute/%s lacks one valid surface classification", [input.metadata.name])
}

deny contains msg if {
  input.kind == "IngressRoute"
  input.metadata.annotations["rs.io/surface"] == "public-human"
  input.spec.entryPoints != ["public"]
  msg := sprintf("IngressRoute/%s public surface must bind only public", [input.metadata.name])
}

deny contains msg if {
  input.kind == "IngressRoute"
  input.metadata.annotations["rs.io/surface"] == "private-operator"
  input.spec.entryPoints != ["private"]
  msg := sprintf("IngressRoute/%s private surface must bind only private", [input.metadata.name])
}

deny contains msg if {
  input.kind == "IngressRoute"
  input.metadata.annotations["rs.io/surface"] != "private-operator"
  some route in input.spec.routes
  contains(route.match, "/v1/operator/")
  msg := sprintf("IngressRoute/%s publishes a private operator path", [input.metadata.name])
}

deny contains msg if {
  input.kind == "StorageClass"
  input.metadata.name == "encrypted-gp3"
  object.get(input.parameters, "encrypted", "") != "true"
  msg := "StorageClass/encrypted-gp3 must enable EBS encryption"
}

deny contains msg if {
  input.kind == "Cluster"
  input.apiVersion == "postgresql.cnpg.io/v1"
  input.spec.instances != 1
  msg := sprintf("Cluster/%s must remain explicitly single-primary", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkFlow"
  flow := {
    "source": input.spec.source,
    "destination": input.spec.destination,
    "port": input.spec.port,
  }
  input.spec.expected == "allow"
  not flow in allowed_flows
  msg := sprintf("NetworkFlow/%s claims an undeclared flow is allowed", [input.metadata.name])
}

deny contains msg if {
  input.kind == "NetworkFlow"
  flow := {
    "source": input.spec.source,
    "destination": input.spec.destination,
    "port": input.spec.port,
  }
  input.spec.expected == "deny"
  flow in allowed_flows
  msg := sprintf("NetworkFlow/%s denies a required flow", [input.metadata.name])
}
