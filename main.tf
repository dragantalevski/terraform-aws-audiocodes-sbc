terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
  required_version = ">= 1.0"
}

locals {
  ac_sbc_user_data = "#ini-incremental\nAwsEc2Endpoint=${var.ec2_endpoint}\n[ WebUsers ]\nFORMAT WebUsers_Index = WebUsers_Username, WebUsers_Password, WebUsers_Status, WebUsers_PwAgeInterval, WebUsers_SessionLimit, WebUsers_CliSessionLimit, WebUsers_SessionTimeout, WebUsers_BlockTime, WebUsers_UserLevel, WebUsers_PwNonce;\nWebUsers 0 = \"Admin\", \"$1$WWs+aT5lbztSUFVSBV1fAg5RWl8OCwxcSUdGQk1NFEdKTh5NRBhPTLm547bmvLGwvLm77r3pubnxpqCm96z0r/w=38104915834\", 1, 0, 5, -1, 15, 60, 200, \"2311866a5bbb4569cf809324a6d211462e884db970cc7b7c\";\n[ \\WebUsers ]\n[ CpMediaRealm ]\nFORMAT Index = MediaRealmName, IPv4IF, PortRangeStart, MediaSessionLeg, PortRangeEnd, IsDefault;\nCpMediaRealm 0 = CpMediaRealm_0, eth2:1, 6000, 14883, 65531, 1;\n[ \\CpMediaRealm ]\n\n[ SIPInterface ]\nFORMAT Index = InterfaceName, NetworkInterface;\nSIPInterface 0 = SIPInterface_0, eth2:1;\n[ \\SIPInterface ]\n\n\n#cloud-end\n"
}


## SBC-1(Active)

resource "aws_instance" "ac_sbc1" {
  ami                  = var.ac_sbc_image_id
  instance_type        = var.instance_type 
  key_name             = var.ac_sbc_key
  iam_instance_profile = var.ac_sbc_instance_profile_name
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
    for_each = var.root_ebs
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
    {
      Name = "${var.ec2_name}a"
    }
  )
  tags = merge(
    var.tags,
    {
      Name           = "${var.ec2_name}a"
    }
  )
  user_data_base64 = base64encode(
    join("\n", [
      "#ini-file",
      "HARemoteAddress = '${aws_network_interface.ac_sbc2_eth0.private_ip}'",
      "HAPriority = 2",
      "HAUnitIdName = '${var.ec2_name}a'",
      "#network_layout=2",
      "#network-interfaces",
      "iface eth1:1",
      "dns 0.0.0.0",
      "iface eth2:1",
      "dns 0.0.0.0",
      "iface eth3:1",
      "dns 0.0.0.0",
      local.ac_sbc_user_data
    ])
  )
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_network_interface" "ac_sbc1_eth0" {
  subnet_id         = var.ac_sbc_eth0_subnet_id
  private_ips       = [var.ac_sbc1_eth0_ip]
  security_groups   = [aws_security_group.sg_ac_sbc_ha.id]
  source_dest_check = true
  tags = {
    Name = "interface_${var.ec2_name}a_eth0"
  }
}

resource "aws_network_interface" "ac_sbc1_eth1" {
  subnet_id               = var.ac_sbc_eth1_subnet_id
  private_ip_list_enabled = true
  private_ip_list         = [var.ac_sbc1_eth1_ip, var.ac_sbc_eth1_ip]
  security_groups         = [aws_security_group.sg_ac_sbc_oam.id]
  source_dest_check       = true
  tags = {
    Name   = "interface_${var.ec2_name}a_eth1"
  }
}
resource "aws_network_interface_attachment" "ac_sbc1_eth1" {
  instance_id          = aws_instance.ac_sbc1.id
  network_interface_id = aws_network_interface.ac_sbc1_eth1.id
  device_index         = 1
}

resource "aws_network_interface" "ac_sbc1_eth2" {
  subnet_id               = var.ac_sbc_eth2_subnet_id
  private_ip_list_enabled = true
  private_ip_list         = [var.ac_sbc1_eth2_ip, var.ac_sbc_eth2_ip]
  security_groups         = [aws_security_group.sg_ac_sbc_voip_internal.id]
  source_dest_check       = true
  tags = {
    Name   = "interface_${var.ec2_name}a_eth2"
  }
}
resource "aws_network_interface_attachment" "ac_sbc1_eth2" {
  instance_id          = aws_instance.ac_sbc1.id
  network_interface_id = aws_network_interface.ac_sbc1_eth2.id
  device_index         = 2
}

resource "aws_network_interface" "ac_sbc1_eth3" {
  count                   = var.ac_sbc_eth3_enable ? 1 : 0
  subnet_id               = var.ac_sbc_eth3_subnet_id
  private_ip_list_enabled = true
  private_ip_list         = [var.ac_sbc1_eth3_ip, var.ac_sbc_eth3_ip]
  security_groups         = [aws_security_group.sg_ac_sbc_voip_external[0].id]
  source_dest_check       = true
  tags = {
    Name = "interface_${var.ec2_name}a_eth3"
  }
}
resource "aws_network_interface_attachment" "ac_sbc1_eth3" {
  count                = var.ac_sbc_eth3_enable ? 1 : 0
  instance_id          = aws_instance.ac_sbc1.id
  network_interface_id = aws_network_interface.ac_sbc1_eth3[0].id
  device_index         = 3
}

resource "aws_eip" "ac_sbc_eth3_dynamic" {
  count = var.ac_sbc_eth3_enable && var.ac_sbc_eth3_public_enable && var.ac_sbc_eth3_public_ip == "" ? 1 : 0
  tags = {
    Name = "${var.ec2_name}_eip_01"
  }
}

resource "aws_eip_association" "ac_sbc_eth3" {
  count = var.ac_sbc_eth3_enable && var.ac_sbc_eth3_public_enable && (
  var.ac_sbc_eth3_public_ip != "" || length(aws_eip.ac_sbc_eth3_dynamic) > 0) ? 1 : 0
  allocation_id        = var.ac_sbc_eth3_public_ip != "" ? var.ac_sbc_eth3_public_ip : aws_eip.ac_sbc_eth3_dynamic[0].id
  network_interface_id = aws_network_interface.ac_sbc1_eth3[0].id
  private_ip_address   = aws_network_interface.ac_sbc1_eth3[0].private_ip_list[1]
  depends_on           = [aws_network_interface.ac_sbc1_eth3]
}


resource "aws_cloudwatch_metric_alarm" "recovery_alarm_sbc1" {
  alarm_name          = "recoveryAlarm-${var.ec2_name}a"
  alarm_description   = "Trigger a recovery when instance status check fails for 60 consecutive seconds."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  alarm_actions = [
    "arn:aws:automate:${data.aws_region.current.region}:ec2:recover"
  ]
  dimensions = {
    InstanceId = aws_instance.ac_sbc1.id
  }
}




## SBC-2 (Standby)

resource "aws_instance" "ac_sbc2" {
  ami                  = var.ac_sbc_image_id
  instance_type        = var.instance_type # "Recommended instance types: m5n.xlarge for media forwarding; c5n.2xlarge or c5n.9xlarge for transcoding."
  key_name             = var.ac_sbc_key
  iam_instance_profile = var.ac_sbc_instance_profile_name
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
    for_each = var.root_ebs
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
    {
      Name = "${var.ec2_name}b"
    }
  )
  tags = merge(
    var.tags,
    {
      Name           = "${var.ec2_name}b"
    }
  )
  user_data_base64 = base64encode(
    join("\n", [
      "#ini-file",
      "HARemoteAddress = '${aws_network_interface.ac_sbc1_eth0.private_ip}",
      "HAPriority = 1",
      "HAUnitIdName = '${var.ec2_name}b'",
      "#network_layout=2",
      local.ac_sbc_user_data
    ])
  )
  lifecycle {
    ignore_changes = [ami]
  }
}


resource "aws_network_interface" "ac_sbc2_eth0" {
  subnet_id = var.ac_sbc_eth0_subnet_id

  private_ips       = [var.ac_sbc2_eth0_ip]
  security_groups   = [aws_security_group.sg_ac_sbc_ha.id]
  source_dest_check = true
  tags = {
    Name = "interface_${var.ec2_name}b_eth0"
  }
}

resource "aws_network_interface" "ac_sbc2_eth1" {
  subnet_id               = var.ac_sbc_eth1_subnet_id
  private_ip_list_enabled = true
  private_ip_list         = [var.ac_sbc2_eth1_ip]
  security_groups         = [aws_security_group.sg_ac_sbc_oam.id]
  source_dest_check       = true
  tags = {
    Name   = "interface_${var.ec2_name}b_eth1"
  }
}
resource "aws_network_interface_attachment" "ac_sbc2_eth1" {
  instance_id          = aws_instance.ac_sbc2.id
  network_interface_id = aws_network_interface.ac_sbc2_eth1.id
  device_index         = 1
}

resource "aws_network_interface" "ac_sbc2_eth2" {
  subnet_id               = var.ac_sbc_eth2_subnet_id
  private_ip_list_enabled = true
  private_ip_list         = [var.ac_sbc2_eth2_ip]
  security_groups         = [aws_security_group.sg_ac_sbc_voip_internal.id]
  source_dest_check       = true
  tags = {
    Name   = "interface_${var.ec2_name}b_eth2"
  }
}
resource "aws_network_interface_attachment" "ac_sbc2_eth2" {
  instance_id          = aws_instance.ac_sbc2.id
  network_interface_id = aws_network_interface.ac_sbc2_eth2.id
  device_index         = 2
}

resource "aws_network_interface" "ac_sbc2_eth3" {
  count                   = var.ac_sbc_eth3_enable ? 1 : 0
  subnet_id               = var.ac_sbc_eth3_subnet_id
  private_ip_list_enabled = true
  private_ip_list         = [var.ac_sbc2_eth3_ip]
  security_groups         = [aws_security_group.sg_ac_sbc_voip_external[0].id]
  source_dest_check       = true
  tags = {
    Name = "interface_${var.ec2_name}b_eth3"
  }
}
resource "aws_network_interface_attachment" "ac_sbc2_eth3" {
  count                = var.ac_sbc_eth3_enable ? 1 : 0
  instance_id          = aws_instance.ac_sbc2.id
  network_interface_id = aws_network_interface.ac_sbc2_eth3[0].id
  device_index         = 3
}


resource "aws_cloudwatch_metric_alarm" "recovery_alarm_sbc2" {
  alarm_name          = "recoveryAlarm-${var.ec2_name}b"
  alarm_description   = "Trigger a recovery when instance status check fails for 60 consecutive seconds."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 1
  comparison_operator = "GreaterThanThreshold"
  threshold           = 0
  alarm_actions = [
    "arn:aws:automate:${data.aws_region.current.region}:ec2:recover"
  ]
  dimensions = {
    InstanceId = aws_instance.ac_sbc2.id
  }
}