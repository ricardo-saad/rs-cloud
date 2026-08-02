package main

import rego.v1

document := json.marshal(input)

deny contains "promotion marker REPLACE_AT_PROMOTION remains" if {
  contains(document, "REPLACE_AT_PROMOTION")
}

deny contains "non-promotable all-zero image digest remains" if {
  contains(document, "sha256:0000000000000000000000000000000000000000000000000000000000000000")
}

deny contains "documentation-only private source CIDR remains" if {
  contains(document, "192.0.2.0/24")
}

deny contains msg if {
  marker := object.get(object.get(input.metadata, "annotations", {}), "rs.io/promotion-placeholder", "")
  marker != ""
  msg := sprintf("%s/%s remains promotion-blocked by %s", [input.kind, input.metadata.name, marker])
}
