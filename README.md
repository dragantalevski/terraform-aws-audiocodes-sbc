# Terraform AWS AudioCodes SBC VE HA Module

This Terraform module deploys a High-Availability (HA) pair of AudioCodes Session Border Controllers (SBCs) on AWS EC2.

The module provisions two EC2 instances, each with multiple network interfaces for management, HA, and media traffic, and sets up the initial user data for HA configuration.

## Features

- Deploys a two-node SBC cluster for High Availability.
- Configures multiple ENIs for network segmentation (HA, OAM, Media).
- Supports an optional fourth ENI for external media, with EIP association.
- Configures EC2 recovery alarms for each instance.
- Highly customizable through input variables.

## Usage Example

Here's how you might use this module in your own Terraform code:

```hcl
module "audiocodes_sbc" {
  source = "your-git-repo/terraform-aws-audiocodes-sbc/v1.0.0"

  name                 = "sbc-cluster-prod"
  ami_id               = "ami-0123456789abcdef0" # AudioCodes SBC AMI
  instance_type        = "m5n.xlarge"
  ec2_endpoint         = "ec2.eu-central-1.amazonaws.com"

  subnets = {
    ha             = "subnet-000011112222ha"
    oam            = "subnet-000011112222oam"
    internal_media = "subnet-000011112222int"
    external_media = "subnet-000011112222ext"
  }

  private_ips = {
    sbc-01a = {
      eth0 = "10.0.1.10"
      eth1 = "10.0.2.10"
      eth2 = "10.0.3.10"
      eth3 = "10.0.4.10"
    }
    sbc-01b = {
      eth0 = "10.0.1.11"
      eth1 = "10.0.2.11"
      eth2 = "10.0.3.11"
      eth3 = "10.0.4.11"
    }
    shared = {
      eth1 = "10.0.2.12" # Floating IP for OAM
      eth2 = "10.0.3.12" # Floating IP for Internal Media
      eth3 = "10.0.4.12" # Floating IP for External Media
    }
  }

  enable_eth3              = true
  eth3_eip_allocation_id   = "eipalloc-0123456789abcdef0"

  tags = {
    Environment = "prod"
    Owner       = "voice-team"
  }
}
```

## Prerequisites

Before using this module, you must have the following resources created in AWS:

1.  An **AudioCodes SBC AMI**.
2.  **Subnets** for each network interface (HA, OAM, Media).
3.  An **EC2 Key Pair**.
4.  An **IAM Instance Profile** with necessary permissions.
5.  (Optional) An allocated **Elastic IP** if you plan to use the external media interface.

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| `name` | A name for the SBC deployment, used as a prefix for all created resources. | `string` | n/a | yes |
| `ami_id` | The AMI ID for the AudioCodes SBC instance. | `string` | n/a | yes |
| `instance_type` | The EC2 instance type for the SBCs. | `string` | `"m5n.xlarge"` | no |
| `key_name` | The name of the EC2 key pair to associate with the instances. | `string` | n/a | yes |
| `iam_instance_profile` | The name of the IAM instance profile to associate with the instances. | `string` | n/a | yes |
| `subnets` | A map of subnet IDs for each network interface. Keys: `ha`, `oam`, `internal_media`, `external_media`. | `map(string)` | n/a | yes |
| `security_group_ids` | A map of security group IDs for each network interface. Keys: `ha`, `oam`, `internal_media`, `external_media`. | `map(string)` | n/a | yes |
| `private_ips` | An object defining the static private IP addresses for each interface on both SBCs, plus the shared floating IPs. | `object` | n/a | yes |
| `ec2_endpoint` | The EC2 endpoint for the target AWS region (e.g., `ec2.us-east-1.amazonaws.com`). Required for user data. | `string` | n/a | yes |
| `enable_eth3` | If true, the third network interface (eth3, typically for external media) will be created. | `bool` | `false` | no |
| `eth3_eip_allocation_id` | The Allocation ID of an Elastic IP to associate with the shared IP on eth3 of the primary SBC. | `string` | `""` | no |
| `root_block_device` | A list of maps defining the root EBS volume. See Terraform `aws_instance` documentation. | `any` | `[{}]` | no |
| `tags` | A map of additional tags to apply to all resources. | `map(string)` | `{}` | no |
| `eni_tags` | A map of additional tags to apply to specific network interfaces. | `any` | `{...}` | no |

## Outputs

| Name | Description |
|------|-------------|
| `sbc_instances` | A map containing the full `aws_instance` objects for both SBCs. |
| `network_interfaces` | A map containing the full `aws_network_interface` objects for all created ENIs. |

---
More information on the AudioCodes SBC can be found in the [official installation manual](https://www.audiocodes.com/media/eiwnmvt1/mediant-virtual-edition-sbc-for-amazon-aws-installation-manual-ver-76.pdf).
```

### 2. Variables

This `variables.tf` file defines the public API for your module. I've used complex types like `object` and `map` to group related variables, making them easier to manage.

```tf:terraform/modules/ac_sbc/variables.tf
variable "name" {
  description = "A name for the SBC deployment, used as a prefix for all created resources."
  type        = string
}

variable "tags" {
  description = "A map of additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}

// *******************************************************************
// ** EC2 Instance Configuration
// *******************************************************************

variable "ami_id" {
  description = "The AMI ID for the AudioCodes SBC instance."
  type        = string
}

variable "instance_type" {
  description = "The EC2 instance type for the SBCs. Recommended: m5n.xlarge for media, c5n.2xlarge+ for transcoding."
  type        = string
  default     = "m5n.xlarge"
}


variable "root_block_device" {
  description = "A list of maps defining the root EBS volume. See Terraform aws_instance documentation."
  type        = any
  default     = [{}] # Use AWS defaults
}

variable "ec2_endpoint" {
  description = "The EC2 endpoint for the target AWS region (e.g., `ec2.us-east-1.amazonaws.com`). Required for user data."
  type        = string
}

// *******************************************************************
// ** Networking Configuration
// *******************************************************************

variable "subnets" {
  description = "A map of subnet IDs for each network interface. Keys: ha, oam, internal_media, external_media (optional)."
  type        = map(string)
}


variable "private_ips" {
  description = "An object defining the static private IP addresses for each interface on both SBCs, plus the shared floating IPs."
  type = object({
    sbc1 = object({
      eth0 = string
      eth1 = string
      eth2 = string
      eth3 = optional(string)
    })
    sbc2 = object({
      eth0 = string
      eth1 = string
      eth2 = string
      eth3 = optional(string)
    })
    shared = object({
      eth1 = string
      eth2 = string
      eth3 = optional(string)
    })
  })
}

variable "enable_eth3" {
  description = "If true, the third network interface (eth3, typically for external media) will be created."
  type        = bool
  default     = false
}

variable "eth3_eip_allocation_id" {
  description = "The Allocation ID of an Elastic IP to associate with the shared IP on eth3 of the primary SBC."
  type        = string
  default     = ""
}

variable "eni_tags" {
  description = "A map of additional tags to apply to specific network interfaces."
  type = object({
    sbc1 = optional(object({
      eth1 = optional(map(string), {})
      eth2 = optional(map(string), {})
      eth3 = optional(map(string), {})
    }), {})
    sbc2 = optional(object({
      eth1 = optional(map(string), {})
      eth2 = optional(map(string), {})
      eth3 = optional(map(string), {})
    }), {})
  })
  default = {}
}
```

### 3. Main Logic

The `main.tf` is now refactored to use the new variables. It's cleaner and contains no project-specific hardcoded values.

```tf:terraform/modules/ac_sbc/main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0" # Loosened for broader compatibility
    }
  }
  required_version = ">= 1.3"
}

data "aws_region" "current" {}

locals {
  # This user data is common for both instances
  ac_sbc_common_user_data = "#ini-incremental\nAwsEc2Endpoint=${var.ec2_endpoint}\n[ WebUsers ]\nFORMAT WebUsers_Index = WebUsers_Username, WebUsers_Password, WebUsers_Status, WebUsers_PwAgeInterval, WebUsers_SessionLimit, WebUsers_CliSessionLimit, WebUsers_SessionTimeout, WebUsers_BlockTime, WebUsers_UserLevel, WebUsers_PwNonce;\nWebUsers 0 = \"Admin\", \"$1$WWs+aT5lbztSUFVSBV1fAg5RWl8OCwxcSUdGQk1NFEdKTh5NRBhPTLm547bmvLGwvLm77r3pubnxpqCm96z0r/w=38104915834\", 1, 0, 5, -1, 15, 60, 200, \"2311866a5bbb4569cf809324a6d211462e884db970cc7b7c\";\n[ \\WebUsers ]\n[ CpMediaRealm ]\nFORMAT Index = MediaRealmName, IPv4IF, PortRangeStart, MediaSessionLeg, PortRangeEnd, IsDefault;\nCpMediaRealm 0 = CpMediaRealm_0, eth2:1, 6000, 14883, 65531, 1;\n[ \\CpMediaRealm ]\n\n[ SIPInterface ]\nFORMAT Index = InterfaceName, NetworkInterface;\nSIPInterface 0 = SIPInterface_0, eth2:1;\n[ \\SIPInterface ]\n\n\n#cloud-end\n"

  # Tags applied to all resources
  common_tags = merge(
    var.tags,
    {
      "sbc-cluster" = var.name
    }
  )
}

################################################################################
# SBC-1 (Primary)
################################################################################

resource "aws_instance" "ac_sbc1" {
  ami                  = var.ami_id
  instance_type        = var.instance_type
  key_name             = var.key_name
  iam_instance_profile = var.iam_instance_profile

  primary_network_interface {
    network_interface_id = aws_network_interface.ac_sbc1_eth0.id
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  dynamic "root_block_device" {
    for_each = var.root_block_device
    content {
      delete_on_termination = lookup(root_block_device.value, "delete_on_termination", true)
      encrypted             = lookup(root_block_device.value, "encrypted", true)
      iops                  = lookup(root_block_device.value, "iops", null)
      kms_key_id            = lookup(root_block_device.value, "kms_key_id", null)
      volume_size           = lookup(root_block_device.value, "volume_size", null)
      volume_type           = lookup(root_block_device.value, "volume_type", null)
    }
  }

  volume_tags = merge(
    local.common_tags,
    { Name = "${var.name}-sbc1" }
  )

  tags = merge(
    local.common_tags,
    {
      Name           = "${var.name}-sbc1"
      backup_enabled = true # Retained from original
      backup_class   = "its-ec2-silver" # Retained from original
    }
  )

  user_data_base64 = base64encode(
    join("\n", [
      "#ini-file",
      "HARemoteAddress = '${var.private_ips.sbc2.eth0}'",
      "HAPriority = 2",
      "HAUnitIdName = '${var.name}-sbc1'",
      "#network_layout=2",
      "#network-interfaces",
      "iface eth1:1",
      "dns 0.0.0.0",
      "iface eth2:1",
      "dns 0.0.0.0",
      var.enable_eth3 ? "iface eth3:1" : "",
      var.enable_eth3 ? "dns 0.0.0.0" : "",
      local.ac_sbc_common_user_data
    ])
  )

  lifecycle {
    ignore_changes = [ami]
  }
}

# --- SBC-1 Network Interfaces ---

resource "aws_network_interface" "ac_sbc1_eth0" {
  subnet_id         = var.subnets["ha"]
  private_ips       = [var.private_ips.sbc1.eth0]
  security_groups   = [var.security_group_ids["ha"]]
  source_dest_check = true
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc1-eth0" }
  )
}

resource "aws_network_interface" "ac_sbc1_eth1" {
  subnet_id       = var.subnets["oam"]
  private_ip_list = [var.private_ips.sbc1.eth1, var.private_ips.shared.eth1]
  security_groups = [var.security_group_ids["oam"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc1-eth1" },
    try(var.eni_tags.sbc1.eth1, {})
  )
}
resource "aws_network_interface_attachment" "ac_sbc1_eth1" {
  instance_id          = aws_instance.ac_sbc1.id
  network_interface_id = aws_network_interface.ac_sbc1_eth1.id
  device_index         = 1
}

resource "aws_network_interface" "ac_sbc1_eth2" {
  subnet_id       = var.subnets["internal_media"]
  private_ip_list = [var.private_ips.sbc1.eth2, var.private_ips.shared.eth2]
  security_groups = [var.security_group_ids["internal_media"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc1-eth2" },
    try(var.eni_tags.sbc1.eth2, {})
  )
}
resource "aws_network_interface_attachment" "ac_sbc1_eth2" {
  instance_id          = aws_instance.ac_sbc1.id
  network_interface_id = aws_network_interface.ac_sbc1_eth2.id
  device_index         = 2
}

resource "aws_network_interface" "ac_sbc1_eth3" {
  count           = var.enable_eth3 ? 1 : 0
  subnet_id       = var.subnets["external_media"]
  private_ip_list = [var.private_ips.sbc1.eth3, var.private_ips.shared.eth3]
  security_groups = [var.security_group_ids["external_media"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc1-eth3" },
    try(var.eni_tags.sbc1.eth3, {})
  )
}
resource "aws_network_interface_attachment" "ac_sbc1_eth3" {
  count                = var.enable_eth3 ? 1 : 0
  instance_id          = aws_instance.ac_sbc1.id
  network_interface_id = aws_network_interface.ac_sbc1_eth3[0].id
  device_index         = 3
}

resource "aws_eip_association" "ac_sbc_eth3" {
  count                = var.enable_eth3 && var.eth3_eip_allocation_id != "" ? 1 : 0
  allocation_id        = var.eth3_eip_allocation_id
  network_interface_id = aws_network_interface.ac_sbc1_eth3[0].id
  private_ip_address   = var.private_ips.shared.eth3
}

resource "aws_cloudwatch_metric_alarm" "recovery_alarm_sbc1" {
  alarm_name          = "sbc-recovery-${var.name}-sbc1"
  alarm_description   = "Trigger a recovery when instance status check fails for 60 consecutive seconds."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  alarm_actions       = ["arn:aws:automate:${data.aws_region.current.name}:ec2:recover"]
  dimensions = {
    InstanceId = aws_instance.ac_sbc1.id
  }
  tags = local.common_tags
}

################################################################################
# SBC-2 (Secondary)
################################################################################

resource "aws_instance" "ac_sbc2" {
  ami                  = var.ami_id
  instance_type        = var.instance_type
  key_name             = var.key_name
  iam_instance_profile = var.iam_instance_profile

  primary_network_interface {
    network_interface_id = aws_network_interface.ac_sbc2_eth0.id
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    http_tokens                 = "required"
    instance_metadata_tags      = "disabled"
  }

  dynamic "root_block_device" {
    for_each = var.root_block_device
    content {
      delete_on_termination = lookup(root_block_device.value, "delete_on_termination", true)
      encrypted             = lookup(root_block_device.value, "encrypted", true)
      iops                  = lookup(root_block_device.value, "iops", null)
      kms_key_id            = lookup(root_block_device.value, "kms_key_id", null)
      volume_size           = lookup(root_block_device.value, "volume_size", null)
      volume_type           = lookup(root_block_device.value, "volume_type", null)
    }
  }

  volume_tags = merge(
    local.common_tags,
    { Name = "${var.name}-sbc2" }
  )

  tags = merge(
    local.common_tags,
    {
      Name           = "${var.name}-sbc2"
      backup_enabled = true
      backup_class   = "its-ec2-silver"
    }
  )

  user_data_base64 = base64encode(
    join("\n", [
      "#ini-file",
      "HARemoteAddress = '${var.private_ips.sbc1.eth0}'",
      "HAPriority = 1",
      "HAUnitIdName = '${var.name}-sbc2'",
      "#network_layout=2",
      local.ac_sbc_common_user_data
    ])
  )

  lifecycle {
    ignore_changes = [ami]
  }
}

# --- SBC-2 Network Interfaces ---

resource "aws_network_interface" "ac_sbc2_eth0" {
  subnet_id       = var.subnets["ha"]
  private_ips     = [var.private_ips.sbc2.eth0]
  security_groups = [var.security_group_ids["ha"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc2-eth0" }
  )
}

resource "aws_network_interface" "ac_sbc2_eth1" {
  subnet_id       = var.subnets["oam"]
  private_ip_list = [var.private_ips.sbc2.eth1]
  security_groups = [var.security_group_ids["oam"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc2-eth1" },
    try(var.eni_tags.sbc2.eth1, {})
  )
}
resource "aws_network_interface_attachment" "ac_sbc2_eth1" {
  instance_id          = aws_instance.ac_sbc2.id
  network_interface_id = aws_network_interface.ac_sbc2_eth1.id
  device_index         = 1
}

resource "aws_network_interface" "ac_sbc2_eth2" {
  subnet_id       = var.subnets["internal_media"]
  private_ip_list = [var.private_ips.sbc2.eth2]
  security_groups = [var.security_group_ids["internal_media"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc2-eth2" },
    try(var.eni_tags.sbc2.eth2, {})
  )
}
resource "aws_network_interface_attachment" "ac_sbc2_eth2" {
  instance_id          = aws_instance.ac_sbc2.id
  network_interface_id = aws_network_interface.ac_sbc2_eth2.id
  device_index         = 2
}

resource "aws_network_interface" "ac_sbc2_eth3" {
  count           = var.enable_eth3 ? 1 : 0
  subnet_id       = var.subnets["external_media"]
  private_ip_list = [var.private_ips.sbc2.eth3]
  security_groups = [var.security_group_ids["external_media"]]
  tags = merge(
    local.common_tags,
    { Name = "eni-${var.name}-sbc2-eth3" },
    try(var.eni_tags.sbc2.eth3, {})
  )
}
resource "aws_network_interface_attachment" "ac_sbc2_eth3" {
  count                = var.enable_eth3 ? 1 : 0
  instance_id          = aws_instance.ac_sbc2.id
  network_interface_id = aws_network_interface.ac_sbc2_eth3[0].id
  device_index         = 3
}

resource "aws_cloudwatch_metric_alarm" "recovery_alarm_sbc2" {
  alarm_name          = "sbc-recovery-${var.name}-sbc2"
  alarm_description   = "Trigger a recovery when instance status check fails for 60 consecutive seconds."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  alarm_actions       = ["arn:aws:automate:${data.aws_region.current.name}:ec2:recover"]
  dimensions = {
    InstanceId = aws_instance.ac_sbc2.id
  }
  tags = local.common_tags
}
```

### 4. Outputs

Finally, the `outputs.tf` file exposes the created resources so they can be referenced by other parts of your infrastructure.

```tf:terraform/modules/ac_sbc/outputs.tf
output "sbc_instances" {
  description = "A map containing the full aws_instance objects for both SBCs."
  value = {
    sbc1 = aws_instance.ac_sbc1
    sbc2 = aws_instance.ac_sbc2
  }
}

output "network_interfaces" {
  description = "A map containing the full aws_network_interface objects for all created ENIs."
  value = {
    sbc1_eth0 = aws_network_interface.ac_sbc1_eth0
    sbc1_eth1 = aws_network_interface.ac_sbc1_eth1
    sbc1_eth2 = aws_network_interface.ac_sbc1_eth2
    sbc1_eth3 = one(aws_network_interface.ac_sbc1_eth3[*])
    sbc2_eth0 = aws_network_interface.ac_sbc2_eth0
    sbc2_eth1 = aws_network_interface.ac_sbc2_eth1
    sbc2_eth2 = aws_network_interface.ac_sbc2_eth2
    sbc2_eth3 = one(aws_network_interface.ac_sbc2_eth3[*])
  }
}
