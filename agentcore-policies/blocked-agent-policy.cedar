// Example Cedar policy for Amazon Bedrock AgentCore Policy.
// Purpose: block high-risk runtime agent actions unless governance and safety checks pass.

forbid(
  principal is AgentCore::IamEntity,
  action == AgentCore::Action::"AIGovernanceTools___invoke_production_action",
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/ai-governance-demo"
)
unless {
  context.input has impactAssessmentCompleted &&
  context.input.impactAssessmentCompleted == true &&
  context.input has riskAccepted &&
  context.input.riskAccepted == true &&
  context.input has productionApproved &&
  context.input.productionApproved == true &&
  context.input has guardrailAction &&
  context.input.guardrailAction == "NONE"
};

forbid(
  principal is AgentCore::IamEntity,
  action,
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/ai-governance-demo"
)
when {
  context.input has guardrailAction &&
  context.input.guardrailAction == "BLOCKED"
};

