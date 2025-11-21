## OAM Security Group ( Management Traffic)

resource "aws_security_group" "sg_ac_sbc_oam" {
  name        = "sg_${var.ec2_name}_oam"
  description = "${var.ec2_name} Security Group OAM traffic"
  vpc_id      = var.vpc_id
  lifecycle {
    # Necessary if changing 'name' or 'name_prefix' properties.
    create_before_destroy = true
  }
  tags = {
    Name = "sg_${var.ec2_name}_oam"
  }
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_oam_https" {
  security_group_id = aws_security_group.sg_ac_sbc_oam.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "HTTPS"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_oam_ssh" {
  security_group_id = aws_security_group.sg_ac_sbc_oam.id
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "SSH"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_oam_snmp" {
  security_group_id = aws_security_group.sg_ac_sbc_oam.id
  from_port         = 161
  to_port           = 161
  ip_protocol       = "udp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "SNMP"
}


resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_oam_icmp" {
  security_group_id = aws_security_group.sg_ac_sbc_oam.id
  from_port         = -1
  to_port           = -1
  ip_protocol       = "icmp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "ICMP"
}

resource "aws_vpc_security_group_egress_rule" "sg_ac_sbc_oam_https" {
  security_group_id = aws_security_group.sg_ac_sbc_oam.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "HTTPS"
}

resource "aws_vpc_security_group_egress_rule" "sg_ac_sbc_oam_all" {
  security_group_id = aws_security_group.sg_ac_sbc_oam.id
  from_port         = -1
  to_port           = -1
  ip_protocol       = "-1"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "Allow ALL Traffic"
}



## HA Security Group

resource "aws_security_group" "sg_ac_sbc_ha" {
  name        = "sg_${var.ec2_name}_ha"
  description = "${var.ec2_name} Security Group HA traffic"
  vpc_id      = var.vpc_id
  lifecycle {
    # Necessary if changing 'name' or 'name_prefix' properties.
    create_before_destroy = true
  }
  tags = {
    Name = "sg_${var.ec2_name}_ha"
  }
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_ha_https" {
  security_group_id            = aws_security_group.sg_ac_sbc_ha.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.sg_ac_sbc_ha.id
  description                  = "HTTPS"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_ha_http" {
  security_group_id            = aws_security_group.sg_ac_sbc_ha.id
  from_port                    = 80
  to_port                      = 80
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.sg_ac_sbc_ha.id
  description                  = "HTTP"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_ha_custom_2442" {
  security_group_id            = aws_security_group.sg_ac_sbc_ha.id
  from_port                    = 2442
  to_port                      = 2442
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.sg_ac_sbc_ha.id
  description                  = "Custom_2442"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_ha_custom_669" {
  security_group_id            = aws_security_group.sg_ac_sbc_ha.id
  from_port                    = 669
  to_port                      = 669
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.sg_ac_sbc_ha.id
  description                  = "Custom_669"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_ha_custom_680" {
  security_group_id            = aws_security_group.sg_ac_sbc_ha.id
  from_port                    = 680
  to_port                      = 680
  ip_protocol                  = "udp"
  referenced_security_group_id = aws_security_group.sg_ac_sbc_ha.id
  description                  = "Custom_680"
}

resource "aws_vpc_security_group_egress_rule" "sg_ac_sbc_ha_https" {
  security_group_id = aws_security_group.sg_ac_sbc_ha.id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "Communication with EC2 API endpoint."
}

resource "aws_vpc_security_group_egress_rule" "sg_ac_sbc_ha_meta-data" {
  security_group_id = aws_security_group.sg_ac_sbc_ha.id
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "169.254.169.254/32"
  description       = "Communication with EC2 instance meta-data service"
}


resource "aws_vpc_security_group_egress_rule" "sg_ac_sbc_ha_all" {
  security_group_id            = aws_security_group.sg_ac_sbc_ha.id
  from_port                    = -1
  to_port                      = -1
  ip_protocol                  = "-1"
  referenced_security_group_id = aws_security_group.sg_ac_sbc_ha.id
  description                  = "Internal traffic between Median VE instances"
}



## VOIP Security Group ( Internal VOIP Traffic)

resource "aws_security_group" "sg_ac_sbc_voip_internal" {
  name        = "sg_${var.ec2_name}_voip_internal"
  description = "${var.ec2_name} Security Group VOIP Internal traffic"
  vpc_id      = var.vpc_id
  lifecycle {
    # Necessary if changing 'name' or 'name_prefix' properties.
    create_before_destroy = true
  }
  tags = {
    Name = "sg_${var.ec2_name}_voip_internal"
  }
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_voip_internal_sip_tcp" {
  security_group_id = aws_security_group.sg_ac_sbc_voip_internal.id
  from_port         = 5060
  to_port           = 5061
  ip_protocol       = "tcp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "SIP TCP"
}
resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_voip_internal_sip_udp" {
  security_group_id = aws_security_group.sg_ac_sbc_voip_internal.id
  from_port         = 5060
  to_port           = 5060
  ip_protocol       = "udp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "SIP UDP"
}

resource "aws_vpc_security_group_ingress_rule" "sg_ac_sbc_voip_internal_media" {
  security_group_id = aws_security_group.sg_ac_sbc_voip_internal.id
  from_port         = 16384
  to_port           = 32383
  ip_protocol       = "udp"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "RTP Media"
}

resource "aws_vpc_security_group_egress_rule" "sg_ac_sbc_voip_internal_all" {
  security_group_id = aws_security_group.sg_ac_sbc_voip_internal.id
  from_port         = -1
  to_port           = -1
  ip_protocol       = "-1"
  cidr_ipv4         = "10.0.0.0/8"
  description       = "Allow ALL Traffic"
}

## VOIP Security Group ( External VOIP Traffic)

resource "aws_security_group" "sg_ac_sbc_voip_external" {
  count       = var.ac_sbc_eth3_enable ? 1 : 0
  name        = "sg_${var.ec2_name}_voip_external"
  description = "${var.ec2_name} Security Group VOIP External traffic"
  vpc_id      = var.vpc_id
  lifecycle {
    # Necessary if changing 'name' or 'name_prefix' properties.
    create_before_destroy = true
  }
  tags = {
    Name = "sg_${var.ec2_name}_voip_external"
  }
}

resource "aws_vpc_security_group_ingress_rule" "dynamic_ingress_rules" {
  for_each          = { for idx, rule in var.voip_external_ingress_rules : idx => rule }
  security_group_id = aws_security_group.sg_ac_sbc_voip_external[0].id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.description
  depends_on        = [aws_security_group.sg_ac_sbc_voip_external]
}

resource "aws_vpc_security_group_egress_rule" "dynamic_egress_rules" {
  for_each          = { for idx, rule in var.voip_external_egress_rules : idx => rule }
  security_group_id = aws_security_group.sg_ac_sbc_voip_external[0].id
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  ip_protocol       = each.value.protocol
  cidr_ipv4         = each.value.cidr_ipv4
  description       = each.value.description
  depends_on        = [aws_security_group.sg_ac_sbc_voip_external]
}