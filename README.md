# Terraform AWS AudioCodes SBC VE HA Module

This Terraform module deploys a High-Availability (HA) pair of AudioCodes Session Border Controllers (SBCs) on AWS EC2.

The module provisions two EC2 instances, each with multiple network interfaces for management, HA, and media traffic, and sets up the initial user data for HA configuration.

## Features

- Deploys a two-node SBC cluster for High Availability.
- Configures multiple ENIs for network segmentation (HA, OAM, Media).
- Supports an optional fourth ENI (eth3) for external media, with EIP association.
- Configures EC2 recovery alarms for each instance.
- Highly customizable through input variables.

## Usage Example

Here's how you might use this module in your own Terraform code:

```hcl
module "audiocodes-sbc-ve-ha" {
  source  = "dragantalevski/audiocodes-sbc-ve-ha/aws"
  version >= "1.0.3"
  ac_sbc_image_id       = "ami-0e9642364df71b9e5"
  instance_type         = "m5.xlarge"
  ac_sbc_key                   = "ssh key"
  ac_sbc_instance_profile_name = "IAM Role"
  vpc_id                 = "vpc-id"
  #ec2_endpoint          = "vpce-name"
  ac_sbc_eth0_subnet_id = "subnet-ha"

  ac_sbc_eth1_subnet_id = "subnet-oma4"

  ac_sbc_eth2_subnet_id = "subnet-inside-voip"

  ac_sbc_eth3_enable        = true
  ac_sbc_eth3_public_enable = true
  ac_sbc_eth3_subnet_id     = "subnet-outside-voip"

  # Uncomment and edit the firewall rules for external 3rd party connectivity
  # voip_external_ingress_rules = [
  #   { from_port = 5061, to_port = 5061, protocol = "tcp", cidr_ipv4 = "<3rd Party SBC>", description = "SIP TLS" },
  #   { from_port = 20000, to_port = 27999, protocol = "udp", cidr_ipv4 = "<3rd Party SBC>", description = "Media" }
  # ]
  # voip_external_egress_rules = [
  #   { from_port = 5061, to_port = 5061, protocol = "tcp", cidr_ipv4 = "<3rd Party SBC>", description = "SIP TLS" },
  #   { from_port = 5000, to_port = 65000, protocol = "udp", cidr_ipv4 = "<3rd Party SBC>", description = "Media" }
  # ]
  tags = {
  }
  providers = {
    aws = aws.<region_alias>
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

