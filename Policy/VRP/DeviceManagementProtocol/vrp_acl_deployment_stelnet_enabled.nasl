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
  script_oid("1.3.6.1.4.1.25623.1.0.150241");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Deploying an ACL When the STelnet Service Is Enabled");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "vrp_ssh_server_status.nasl", "vrp_current_configuration_ssh.nasl", "vrp_current_configuration_user_interface.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"Configure an ACL to defend against attacks.");

  exit(0);
}

# 3 different checks need to be done:
# 1. STelnet service is enabled (display ssh server status)
# 2. SSH [ipv6] server acl enabled (display current-configuration)
# 3. ACL and ACL IPv6 in vty user-interface (display current-configuration)

include("policy_functions.inc");

port = get_kb_item("huawei/vrp/ssh-login/port");
model = get_kb_item("huawei/vrp/ssh-login/" + port + "/model");
major_version = get_kb_item("huawei/vrp/ssh-login/major_version");

cmd = "display ssh server status; display current-configuration | include ssh; display current-configuration configuration user-interface";
title = "Deploying an ACL When the STelnet Service Is Enabled";
solution = "Configure ACL attack defense.";
test_type = "SSH_Cmd";
default = "ACL Enabled";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!model || !major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine model or version of VRP device.";
}else if(model =~ "^A[RCP]" && major_version =~ "^5"){ # nb: Test doesn't apply to AR/AC/AP devices on VRP V5
  # Don't report anything if test not applicable
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/ssh_status/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current configuration and SSH server status.";
}else{
  # STelnet enabled
  stelnetserver = get_kb_item("Policy/vrp/current_configuration/ssh_status/stelnetipv4server");
  stelnetipv6server = get_kb_item("Policy/vrp/current_configuration/ssh_status/sftpipv6server");
  if(tolower(stelnetserver) == "enable" || tolower(stelnetipv6server) == "enable"){
    if(!ssh_current_configuration = get_kb_item("Policy/vrp/current_configuration/ssh")){
      value = "Error";
      compliant = "incomplete";
      comment = "STelnet is enabled. Can not determine the current SSH configuration.";
    }else{
      # ssh [ipv6] server acl enabled
      if(ssh_current_configuration =~ "ssh server acl" && ssh_current_configuration =~ "ssh ipv6 server acl"){
        if(!user_interface = get_kb_item("Policy/vrp/current_configuration/user_interface")){
          value = "Error";
          compliant = "incomplete";
          comment = "STelnet is enabled. Can not determine the current user-interface vty status.";
        }else{
          # acl and acl ipv6 in vty user-interface enabled
          if(user_interface =~ "acl ipv6" && user_interface =~ "acl [0-9]"){
            value = "STelnet and ACL Enabled";
            compliant = "yes";
          }else{
            value = "STelnet enabled, ACL not enabled";
            compliant = "no";
          }
        }
      }else{
        value = "STelnet enabled, ACL not enabled";
        compliant = "no";
      }
    }
  }else{
    compliant = "yes";
    value = "STelnet disabled";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
