# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150277");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2020-05-15 11:05:34 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Configuring OSPF Authentication");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "vrp_display_ospf_peer_brief.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"OSP authentication is configured to prevent attackers from
attempting to use control plane protocols to destroy entries on which forwarding depends,
such as routes.");

  exit(0);
}

# 3 Phase check
# 1. Get interfaces with display ospf peer brief relationship established
# 2. Check for ospf authentication-mode in current-configuration interface INTERFACE
# 3. Check if ospf authentication-mode is md5 (insecure, fail) in INTERFACE

include("ssh_func.inc");
include("policy_functions.inc");

interfaces_dict = make_array("Ana", "Analogmodem",
"Asy", "Async",
"Dia", "dialer",
"Eth", "Ethernet",
"GE", "GigabitEthernet",
"H", "HSI",
"IMA", "IMA-Group",
"Log", "Logic-Channel",
"Loop", "loopback",
"MTun", "MTunnel",
"S", "serial",
"Tun", "tunnel",
"VE", "virtual Ethernet",
"VT", "Virtual-Template");

cmd = "display ospf peer brief; display current-configuration interface xxx";
title = "Configuring OSPF Authentication";
solution = "Deploy OSPF authentication and preferentially use the encryption algorithm with high
security. If no encryption algorithm with high security is available, use the MD5 algorithm.";
test_type = "SSH_Cmd";
default = "OSPF authentication-mode not md5";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/ospf/peer/brief/empty")){
  value = "No OSPF neighbor relationship established";
  compliant = "yes";
}else{
  interfaces = get_kb_list("Policy/vrp/ospf/peer/brief/interface");
  foreach interface(interfaces){
    if(!sock = ssh_login_or_reuse_connection()){
      value = "Error";
      compliant = "incomplete";
      comment = "No SSH connection to host";
    }

    interface_split = eregmatch(string:interface, pattern:"([A-Z,a-z]+)\s*([0-9,/,\s]+)");
    if(!interface_split)
      continue;

    if(!interfaces_dict[interface_split[1]])
      cmd1 = "display current-configuration interface " + interface;
    else
      cmd1 = "display current-configuration interface " + interfaces_dict[interface_split[1]] + " " + interface_split[2];

    ret = ssh_cmd(socket:sock, cmd:cmd1, return_errors:FALSE, pty:TRUE, nosh:TRUE, timeout:20,
                  retry:10, force_reconnect:TRUE, clear_buffer:TRUE);

    if(ret !~ "ospf authentication-mode" || ret =~ "ospf authentication-mode md5"){
      value = "OSPF neighbor relationship enabled, ospf authentication-mode not secure";
      compliant = "no";
      comment += interface + " ";
    }
  }
  if(!value){
    value = "OSPF neighbor relationship enabled, ospf authentication-mode secure";
    compliant = "yes";
    comment += "All interfaces have ospf authentication not set to md5";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
