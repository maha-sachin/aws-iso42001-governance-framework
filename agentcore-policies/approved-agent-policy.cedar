// Example Cedar policy for Amazon Bedrock AgentCore Policy.
// Purpose: allow only low/medium risk agent tool calls that have governance evidence.

permit(
  principal is AgentCore::IamEntity,
  action in [
    AgentCore::Action::"AIGovernanceTools___read_approved_dataset",
    AgentCore::Action::"AIGovernanceTools___generate_compliance_summary"
  ],
  resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/ai-governance-demo"
)
when {
  context.input has impactAssessmentCompleted &&
  context.input.impactAssessmentCompleted == true &&
  context.input has riskRating &&
  (context.input.riskRating == "low" || context.input.riskRating == "medium") &&
  context.input has productionApproved &&
  context.input.productionApproved == true &&
  context.input has guardrailAction &&
  context.input.guardrailAction == "NONE"
};

