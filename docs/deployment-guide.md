# Deployment Guide (minimal)

1. Copy `terraform/terraform.tfvars.example` to `terraform/terraform.tfvars` and fill values.
2. Change into `terraform/`.
3. Run `terraform init`, `terraform plan`, and `terraform apply`.
4. Enable modules incrementally and review SCP/IAM JSON before applying to organizations.
