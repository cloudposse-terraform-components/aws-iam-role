locals {
  enabled = module.this.enabled
}

module "role" {
  source  = "cloudposse/iam-role/aws"
  version = "0.22.0"

  assume_role_actions      = var.assume_role_actions
  assume_role_conditions   = var.assume_role_conditions
  assume_role_policy       = var.assume_role_policy
  instance_profile_enabled = var.instance_profile_enabled
  managed_policy_arns      = var.managed_policy_arns
  max_session_duration     = var.max_session_duration
  path                     = var.path
  permissions_boundary     = var.permissions_boundary
  policy_description       = var.policy_description
  policy_document_count    = var.policy_document_count
  policy_documents         = var.policy_documents
  policy_name              = var.policy_name
  principals               = var.principals
  role_description         = var.role_description
  use_fullname             = var.use_fullname

  context = module.this.context
}
