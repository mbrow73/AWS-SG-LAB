terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpc_id" {
  type        = string
  description = "VPC ID where security groups will be created"

  validation {
    condition     = can(regex("^vpc-[a-f0-9]{8,17}$", var.vpc_id))
    error_message = "VPC ID must be valid format (vpc-xxxxxxxxx)"
  }
}

variable "security_groups" {
  type = map(object({
    name        = string
    description = string
    tags        = optional(map(string), {})
  }))
  description = "Security groups to create"
  default     = {}
}

variable "ingress_rules" {
  type = list(object({
    security_group_key           = string
    description                  = string
    from_port                    = number
    to_port                      = number
    protocol                     = string
    cidr_blocks                  = optional(list(string))
    ipv6_cidr_blocks             = optional(list(string))
    source_security_group_key    = optional(string)
    referenced_security_group_id = optional(string)
    prefix_list_id               = optional(string)
  }))
  description = "Ingress rules to create"
  default     = []

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.from_port >= -1 && rule.from_port <= 65535
    ])
    error_message = "from_port must be -1 or 0-65535"
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.to_port >= -1 && rule.to_port <= 65535
    ])
    error_message = "to_port must be -1 or 0-65535"
  }

  validation {
    condition = alltrue([
      for rule in var.ingress_rules :
      rule.from_port <= rule.to_port || rule.from_port == -1
    ])
    error_message = "from_port cannot exceed to_port"
  }
}

variable "egress_rules" {
  type = list(object({
    security_group_key           = string
    description                  = string
    from_port                    = number
    to_port                      = number
    protocol                     = string
    cidr_blocks                  = optional(list(string))
    ipv6_cidr_blocks             = optional(list(string))
    source_security_group_key    = optional(string)
    referenced_security_group_id = optional(string)
    prefix_list_id               = optional(string)
  }))
  description = "Egress rules to create"
  default     = []
}

locals {
  ingress_cidr_rules = [
    for rule in var.ingress_rules :
    rule if length(coalesce(rule.cidr_blocks, [])) > 0 || length(coalesce(rule.ipv6_cidr_blocks, [])) > 0
  ]

  ingress_sg_rules = [
    for rule in var.ingress_rules :
    rule if rule.source_security_group_key != null || rule.referenced_security_group_id != null
  ]

  ingress_pl_rules = [
    for rule in var.ingress_rules :
    rule if rule.prefix_list_id != null
  ]

  egress_cidr_rules = [
    for rule in var.egress_rules :
    rule if length(coalesce(rule.cidr_blocks, [])) > 0 || length(coalesce(rule.ipv6_cidr_blocks, [])) > 0
  ]

  egress_sg_rules = [
    for rule in var.egress_rules :
    rule if rule.source_security_group_key != null || rule.referenced_security_group_id != null
  ]

  egress_pl_rules = [
    for rule in var.egress_rules :
    rule if rule.prefix_list_id != null
  ]
}

resource "aws_security_group" "this" {
  for_each = var.security_groups

  name        = each.value.name
  description = each.value.description
  vpc_id      = var.vpc_id

  tags = merge(
    each.value.tags,
    {
      Name      = each.value.name
      ManagedBy = "terraform"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "cidr_ipv4" {
  for_each = {
    for idx, rule in local.ingress_cidr_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-${idx}" => rule
    if length(coalesce(rule.cidr_blocks, [])) > 0
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv4         = each.value.cidr_blocks[0]

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_ingress_rule" "cidr_ipv6" {
  for_each = {
    for idx, rule in local.ingress_cidr_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-ipv6-${idx}" => rule
    if length(coalesce(rule.ipv6_cidr_blocks, [])) > 0
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv6         = each.value.ipv6_cidr_blocks[0]

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_ingress_rule" "sg" {
  for_each = {
    for idx, rule in local.ingress_sg_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-sg-${idx}" => rule
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol

  referenced_security_group_id = coalesce(
    each.value.referenced_security_group_id,
    try(aws_security_group.this[each.value.source_security_group_key].id, null)
  )

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_ingress_rule" "prefix_list" {
  for_each = {
    for idx, rule in local.ingress_pl_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-pl-${idx}" => rule
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol
  prefix_list_id    = each.value.prefix_list_id

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_egress_rule" "cidr_ipv4" {
  for_each = {
    for idx, rule in local.egress_cidr_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-${idx}" => rule
    if length(coalesce(rule.cidr_blocks, [])) > 0
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv4         = each.value.cidr_blocks[0]

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_egress_rule" "cidr_ipv6" {
  for_each = {
    for idx, rule in local.egress_cidr_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-ipv6-${idx}" => rule
    if length(coalesce(rule.ipv6_cidr_blocks, [])) > 0
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv6         = each.value.ipv6_cidr_blocks[0]

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_egress_rule" "sg" {
  for_each = {
    for idx, rule in local.egress_sg_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-sg-${idx}" => rule
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol

  referenced_security_group_id = coalesce(
    each.value.referenced_security_group_id,
    try(aws_security_group.this[each.value.source_security_group_key].id, null)
  )

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

resource "aws_vpc_security_group_egress_rule" "prefix_list" {
  for_each = {
    for idx, rule in local.egress_pl_rules :
    "${rule.security_group_key}-${rule.protocol}-${rule.from_port}-${rule.to_port}-pl-${idx}" => rule
  }

  security_group_id = aws_security_group.this[each.value.security_group_key].id
  description       = each.value.description
  from_port         = each.value.from_port == -1 ? null : each.value.from_port
  to_port           = each.value.to_port == -1 ? null : each.value.to_port
  ip_protocol       = each.value.protocol
  prefix_list_id    = each.value.prefix_list_id

  tags = {
    Name      = each.value.description
    ManagedBy = "terraform"
  }
}

output "security_group_ids" {
  value       = { for k, v in aws_security_group.this : k => v.id }
  description = "Map of security group keys to IDs"
}

output "security_group_arns" {
  value       = { for k, v in aws_security_group.this : k => v.arn }
  description = "Map of security group keys to ARNs"
}
