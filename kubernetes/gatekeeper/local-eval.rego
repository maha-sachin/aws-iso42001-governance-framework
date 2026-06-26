package gatekeeper.ai.workload

required_labels := {
  "ai.governance/policy-id",
  "ai.governance/risk-rating",
  "ai.governance/owner",
}

deny contains finding if {
  input.kind == "Pod"
  input.metadata.labels["workload-type"] == "ai"
  missing := required_labels - {label | input.metadata.labels[label]}
  count(missing) > 0
  finding := {
    "id": "K8S-AI-001",
    "control": "Required AI governance labels",
    "message": sprintf("AI workload is missing required governance labels: %v", [missing]),
    "missing_labels": missing,
  }
}

deny contains finding if {
  input.kind == "Pod"
  input.metadata.labels["workload-type"] == "ai"
  container := input.spec.containers[_]
  container.securityContext.privileged == true
  finding := {
    "id": "K8S-AI-002",
    "control": "Block privileged AI containers",
    "message": sprintf("Privileged container is not allowed for AI workload: %s", [container.name]),
    "container": container.name,
  }
}

deny contains finding if {
  input.kind == "Pod"
  input.metadata.labels["workload-type"] == "ai"
  object.get(input.metadata.annotations, "ai.governance/approved", "") != "true"
  finding := {
    "id": "K8S-AI-003",
    "control": "Require approved AI workload annotation",
    "message": "AI workload annotation ai.governance/approved must be true before deployment",
  }
}

default allow := false

allow if {
  count(deny) == 0
}
