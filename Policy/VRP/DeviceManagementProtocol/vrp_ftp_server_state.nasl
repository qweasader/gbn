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
  script_oid("1.3.6.1.4.1.25623.1.0.150246");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-05-14 07:32:07 +0000 (Thu, 14 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: FTP Server Status");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "vrp_ftp_server_status.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"The FTP protocol is insecure. If the FTP service is not used, disable
it.");

  exit(0);
}

include("policy_functions.inc");

port = get_kb_item("huawei/vrp/ssh-login/port");
model = get_kb_item("huawei/vrp/ssh-login/" + port + "/model");
major_version = get_kb_item("huawei/vrp/ssh-login/major_version");

cmd = "display ftp-server";
title = "Disabling the FTP Service";
solution = "Run the undo ftp server and undo ftp ipv6 server commands to disable the FTP service.";
test_type = "SSH_Cmd";
default = "Disable";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(!model || !major_version){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine model or version of VRP device.";
}else if(model =~ "^CE" && major_version =~ "^8") { # nb: Test doesn't apply to Campus Switch devices on VRP V8
  # Don't report anything if test not applicable
  exit(0);
}else if(model =~ "^(CE|AR|S)" && major_version =~ "^5") { # nb: Test doesn't apply to Campus Switch, Data Center Switch and AR devices on VRP V5
  # Don't report anything if test not applicable
  exit(0);
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/ftpserver/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current FTP service status.";
}else{
  ftp_server = get_kb_item("Policy/vrp/ftpserver/serverstate");
  ftp_ipv6server = get_kb_item("Policy/vrp/ftpserver/ipv6serverstate");
  if(ftp_server == "Enabled" || ftp_ipv6server == "Enabled")
    value = "Enable";
  else
    value = "Disable";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
