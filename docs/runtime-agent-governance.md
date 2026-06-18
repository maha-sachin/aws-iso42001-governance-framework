# Runtime Agent Governance with AgentCore Policy

This project uses OPA/Rego as the pre-deployment governance gate for AWS AI infrastructure. Amazon Bedrock AgentCore Policy can extend the same governance story into runtime by controlling which tools an AI agent can call after deployment.

## Why This Layer Exists

AI governance needs controls at two points:

- Before deployment: verify infrastructure, evidence, risk rating, and approval before resources are provisioned.
- During runtime: verify that an autonomous agent is allowed to call a specific tool with the current user, action, resource, and request context.

OPA/Rego is used for the first layer. AgentCore Policy with Cedar is represented in this project as the second layer.

## Project Files

- `agentcore-policies/approved-agent-policy.cedar`
- `agentcore-policies/blocked-agent-policy.cedar`
- `agentcore-policies/runtime-agent-request.json`
- `web/src/App.tsx` runtime governance page

## Control Flow

```text
Developer changes Terraform or mock AWS AI config
        |
        v
GitHub Actions runs OPA/Rego policy gate
        |
        v
Deployment is approved or blocked before provisioning
        |
        v
AI agent runs behind Amazon Bedrock AgentCore Gateway
        |
        v
AgentCore Policy evaluates Cedar authorization rules
        |
        v
Bedrock Guardrails provides runtime safety signal
        |
        v
Allow or deny the tool call and record audit evidence
```

## How OPA and Cedar Differ

| Layer | Tool | Purpose |
| --- | --- | --- |
| Pre-deployment | OPA/Rego | Validate infrastructure and governance evidence before deployment |
| Infrastructure | Terraform | Define AWS AI resources and governance controls |
| CI/CD | GitHub Actions | Block non-compliant changes before release |
| Runtime authorization | AgentCore Policy/Cedar | Control what agents can do through gateway-level authorization |
| Runtime safety | Bedrock Guardrails | Detect prompt attacks, harmful content, and sensitive data exposure |
| Evidence | Dashboard | Show policy status, violations, and audit context |

## Example Runtime Controls

The included Cedar examples model these controls:

- Permit approved read-only governance tools when impact assessment and production approval are complete.
- Block production tool calls when critical risk has not been accepted.
- Block any tool call when Bedrock Guardrails reports a blocked runtime safety result.

These files are demo artifacts. In a production AWS environment, Cedar policies would be stored in an AgentCore Policy Engine and associated with an AgentCore Gateway.

