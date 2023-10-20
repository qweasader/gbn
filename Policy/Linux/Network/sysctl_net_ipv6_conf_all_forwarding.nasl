# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150146");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-03-05 10:54:30 +0000 (Thu, 05 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: sysctl net.ipv6.conf.all.forwarding");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_and_parse_sysctl.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sysctl.conf");
  script_xref(name:"URL", value:"https://linuxconfig.org/how-to-turn-on-off-ip-forwarding-in-linux");

  script_tag(name:"summary", value:"IP forwarding is used to determine which path a packet can be
sent over multiple networks.

Note: This scripts looks for 'net.ipv6.conf.all.forwarding' setting in 'sysctl -a'.");

  exit(0);
}

include("policy_functions.inc");

cmd = "sysctl net.ipv6.conf.all.forwarding";
title = "sysctl net.ipv6.conf.all.forwarding";
solution = "sysctl -w net.ipv6.conf.all.forwarding=[0,1]";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sysctl/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux/sysctl/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run sysctl command";
}else{
  if(!value = get_kb_item("Policy/linux/sysctl/net.ipv6.conf.all.forwarding")){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not find setting with sysctl";
  }else{
    compliant = policy_setting_exact_match(value:value, set_point:default);
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);