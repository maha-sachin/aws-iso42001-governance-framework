locals {
  ai_governance_policy_model = jsondecode(file("${path.module}/../policies/ai-governance-policy-model.json"))
  corporate_ai_policies      = local.ai_governance_policy_model.corporate_ai_policies
  operational_ai_policies    = local.ai_governance_policy_model.operational_ai_policies
}

resource "null_resource" "corporate_ai_policy" {
  for_each = local.corporate_ai_policies

  triggers = {
    name         = each.value.name
    iso_mapping  = each.value.iso_mapping
    requirements = jsonencode(each.value.requirements)
    aws_mapping  = jsonencode(each.value.aws_mapping)
  }
}

resource "null_resource" "operational_ai_policy" {
  for_each = local.operational_ai_policies

  triggers = {
    name     = each.value.name
    controls = jsonencode(each.value.controls)
  }
}
