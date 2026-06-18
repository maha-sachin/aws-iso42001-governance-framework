# Architecture Diagram

This project is a Policy-as-Code AI governance platform for AWS AI workloads. It maps ISO 42001-inspired governance requirements to automated OPA/Rego checks, CI/CD deployment gates, runtime agent governance examples, compliance evidence, and dashboard visualization.

## Layered Architecture

```mermaid
flowchart TB
  subgraph L1["Layer 1: Governance Layer"]
    CP["Corporate AI Policies"]
    OP["Operational AI Policies"]
    LC["AI Lifecycle Controls"]
  end

  subgraph L2["Layer 2: Enforcement Layer"]
    INPUT["Mock AWS Infrastructure"]
    OPA["OPA/Rego Policy Engine"]
    GATE["Node.js Deployment Gate"]
    CICD["GitHub Actions"]
  end

  subgraph RT["Runtime Agent Governance Layer"]
    AGW["AgentCore Gateway"]
    CEDAR["AgentCore Policy / Cedar"]
    GR["Bedrock Guardrails Runtime Signal"]
  end

  subgraph AWS["AWS AI Governance Targets"]
    S3["Amazon S3 and KMS"]
    BEDROCK["Amazon Bedrock"]
    IAM["AWS IAM"]
    LOGS["CloudWatch and Audit Evidence"]
  end

  subgraph L3["Layer 3: Visualization Layer"]
    DASH["React Dashboard"]
    OPAUI["Policies OPA Page"]
    LIFE["AI Lifecycle Page"]
    RUNTIME["Runtime Governance Page"]
    REPORT["Compliance Reports"]
  end

  CP --> OPA
  OP --> OPA
  LC --> OPA
  INPUT --> OPA
  OPA --> GATE
  GATE --> CICD
  CICD --> AGW
  AGW --> CEDAR
  GR --> CEDAR
  CEDAR --> REPORT
  OPA --> S3
  OPA --> BEDROCK
  OPA --> IAM
  GATE --> REPORT
  CICD --> REPORT
  REPORT --> DASH
  OPA --> OPAUI
  LC --> LIFE
  CEDAR --> RUNTIME
  LOGS --> REPORT
```

## CI/CD Policy Gate Flow

```mermaid
flowchart LR
  DEV["Developer changes AWS AI config"] --> GH["Push or Pull Request"]
  GH --> ACTIONS["GitHub Actions Triggered"]
  ACTIONS --> SETUP["Setup and Terraform Validate"]
  SETUP --> A62["A.6.2 Data Governance Check"]
  A62 --> A72["A.7.2 Transparency Check"]
  A72 --> A84["A.8.4 Responsible AI Check"]
  A84 --> SEC["IAM Least Privilege Check"]
  SEC --> DECISION{"Violations found?"}
  DECISION -- Yes --> BLOCK["Deployment Blocked"]
  DECISION -- No --> APPROVE["Deployment Approved"]
  BLOCK --> EVIDENCE["Compliance Evidence"]
  APPROVE --> EVIDENCE
```

## Policy Checks

```mermaid
flowchart TB
  OPA["OPA/Rego Policy"]

  OPA --> DG["DG-001 / A.6.2 S3 encryption"]
  OPA --> TR["TR-001 / A.7.2 Bedrock logging"]
  OPA --> RAI["RAI-001 / A.8.4 Bedrock Guardrails"]
  OPA --> SEC["SEC-001 IAM wildcard blocked"]

  DG --> S3["Amazon S3 + AWS KMS"]
  TR --> BRLOG["Bedrock Invocation Logging"]
  RAI --> BRGR["Bedrock Guardrails"]
  SEC --> IAM["AWS IAM"]
```

## Demo Flow

```mermaid
sequenceDiagram
  participant User as Developer / Interview Demo
  participant Input as Mock Infrastructure
  participant OPA as OPA/Rego
  participant Gate as Deployment Gate Script
  participant CI as GitHub Actions
  participant UI as React Dashboard

  User->>Input: Select failed-example.json
  Input->>OPA: Evaluate deny rules
  OPA-->>Gate: Return violations
  Gate-->>CI: Exit 1
  CI-->>User: Deployment blocked
  Gate-->>UI: Compliance evidence and violations

  User->>Input: Select passed-example.json
  Input->>OPA: Evaluate deny rules
  OPA-->>Gate: Return zero violations
  Gate-->>CI: Exit 0
  CI-->>User: Deployment approved
  Gate-->>UI: Compliance score 100%
```
