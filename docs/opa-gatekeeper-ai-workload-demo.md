# OPA Gatekeeper AI Workload Demo

This folder demonstrates how OPA Gatekeeper can enforce AI workload guardrails in Kubernetes.

The main project uses OPA/Rego for AWS AI infrastructure deployment gates. This demo adds the Kubernetes admission-control pattern that many security automation roles expect.

## What It Enforces

The demo includes three Gatekeeper controls:

| Control | Purpose |
| --- | --- |
| `K8sRequiredAILabels` | Requires AI governance labels on AI workloads |
| `K8sBlockPrivilegedAI` | Blocks privileged containers for AI workloads |
| `K8sApprovedAIWorkload` | Requires approval annotation before deployment |

## Files

```text
kubernetes/gatekeeper/
├── constraint-templates/
│   ├── k8srequiredailabels.yaml
│   ├── k8sblockprivilegedai.yaml
│   └── k8sapprovedaiworkload.yaml
├── constraints/
│   ├── require-ai-governance-labels.yaml
│   ├── block-privileged-ai-containers.yaml
│   └── require-approved-ai-workload.yaml
├── examples/
│   ├── passing-ai-pod.yaml
│   └── failing-ai-pod.yaml
└── local-eval.rego
```

## Local Demo Without a Cluster

The local demo uses OPA to evaluate the same policy intent against sample Kubernetes Pod YAML.

Passing workload:

```bash
npm run gatekeeper:check
```

Expected result:

```text
OPA Gatekeeper AI workload demo: PASS
Violations: 0
```

Failing workload:

```bash
npm run gatekeeper:check:fail
```

Expected result:

```text
OPA Gatekeeper AI workload demo: FAIL
Violations: 3
```

The failing command intentionally exits with status code `1`. This mirrors how an admission or CI gate blocks non-compliant workloads.

## Apply to a Real Kubernetes Cluster

Install Gatekeeper first:

```bash
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/release-3.17/deploy/gatekeeper.yaml
```

Apply the templates and constraints:

```bash
kubectl apply -f kubernetes/gatekeeper/constraint-templates/
kubectl apply -f kubernetes/gatekeeper/constraints/
```

Try the passing workload:

```bash
kubectl apply -f kubernetes/gatekeeper/examples/passing-ai-pod.yaml
```

Try the failing workload:

```bash
kubectl apply -f kubernetes/gatekeeper/examples/failing-ai-pod.yaml
```

Gatekeeper should reject the failing workload because it:

- Missing `ai.governance/policy-id`
- Missing `ai.governance/owner`
- Uses a privileged container
- Does not have `ai.governance/approved: "true"`

## How This Connects to the Main Project

This adds a Kubernetes admission-control layer:

```text
Terraform / AWS AI config
  -> OPA/Rego CI/CD deployment gate
  -> Kubernetes AI workload admission
  -> OPA Gatekeeper constraints
  -> Allow or deny workload creation
```

The project now demonstrates Policy-as-Code across AWS infrastructure, CI/CD, runtime agent authorization concepts, and Kubernetes admission control.

