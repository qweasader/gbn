# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150175");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-03-23 09:50:44 +0000 (Mon, 23 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: kernel.sysrq in /etc/sysctl.conf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_sysctl_d.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"0;1", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sysctl.conf");
  script_xref(name:"URL", value:"https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/");

  script_tag(name:"summary", value:"SysRq enables users with physical access to access dangerous
system-level commands in a computer. Therefore, it is advised to restrict the usage of the SysRq
function.

Note: This scripts looks for 'kernel.sysrq' setting in /etc/sysctl.conf.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'kernel.sysrq' /etc/sysctl.conf";
title = "kernel.sysrq in /etc/sysctl.conf";
solution = "Add or remove 'kernel.sysrq = [0,1]' to /etc/sysctl.conf";
test_type = "SSH_Cmd";
default = script_get_preference("Status", id:1);

if(get_kb_item("Policy/linux/sysctl/conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/sysctl.conf/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/sysctl.conf";
}else{
  content = get_kb_item("Policy/linux//etc/sysctl.conf/content");
  grep = egrep(string:content, pattern:"kernel.sysrq");

  if(grep =~ "^\s*#"){
    value = "None";
  }else{
    match = eregmatch(string:grep, pattern:"kernel\.sysrq\s*=\s*([0-9]+)");
    if(match)
      value = match[1];
    else
      value = "None";
  }
  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);