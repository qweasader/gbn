# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150244");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-05-15 11:05:34 +0000 (Fri, 15 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Deploying IS-IS Authentication");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "vrp_display_isis_peer.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"IS-IS authentication is deployed to prevent attackers from
attempting to use the control plane protocol to destroy entries on which forwarding depends,
such as routes.");

  exit(0);
}

# 3 Phase step
# 1. Get intrfaces with is-is neighbor realtionship established
# 2. Check for isis authentication-mode in current-configuration interface INTERFACE
# 3. Check if isis authentication-mode is md5 cipher (insecure, fail) in INTERFACE

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

cmd = "display isis peer; display current-configuration interface xxx";
title = "Deploying IS-IS Authentication";
solution = "Deploy IS-IS authentication and preferentially use the encryption algorithm with high
security. If no encryption algorithm with high security is available, use the MD5 algorithm.";
test_type = "SSH_Cmd";
default = "IS-IS authentication enabled";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/isis/peer/empty")){
  value = "No IS-IS neighbor relationship established";
  compliant = "yes";
}else{
  interfaces = get_kb_list("Policy/vrp/isis/peer/interface");
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
    if(ret !~ "isis authentication-mode" || ret =~ "isis authentication-mode md5 cipher"){
      value = "IS-IS neighbor realtionship enabled, isis authentication-mode not secure";
      compliant = "no";
      comment += interface + " ";
    }
  }
  if(!value){
    value = "IS-IS neighbor realtionship enabled, isis authentication-mode secure";
    compliant = "yes";
    comment += "All interfaces have isis authentication not set to md5 cipher";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
