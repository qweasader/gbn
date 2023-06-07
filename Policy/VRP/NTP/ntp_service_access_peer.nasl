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
  script_oid("1.3.6.1.4.1.25623.1.0.150291");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-07-13 14:02:06 +0000 (Mon, 13 Jul 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Huawei Data Communication: Setting the NTP Service Access Permission on the Local Device");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "vrp_current_configuration_ntp.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_exclude_keys("huawei/vrp/yunshan/detected");

  script_tag(name:"summary", value:"The ACL is deployed for NTP.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "display current-configuration | include ntp";
title = "Setting the Access Control Rights of the NTP Service on the Local Device";
solution = "Configure an ACL for NTP.";
test_type = "SSH_Cmd";
default = "Enabled";

if(get_kb_item("Policy/vrp/installed/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No VRP device detected.";
}else if(get_kb_item("Policy/vrp/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to VRP device.";
}else if(get_kb_item("Policy/vrp/current_configuration/ntp/disabled")){
  value = "Not applicable";
  compliant = "yes";
  comment = "This check is applicable if NTP is enabled only, but the command did not return anything.";
}else if(!current_configuration = get_kb_item("Policy/vrp/current_configuration/ntp")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not determine the current configuration for ntp.";
}else if(current_configuration !~ "ntp"){
  value = "Not applicable";
  compliant = "yes";
  comment = "This check is applicable if NTP is enabled only. Did not find 'ntp' included in current-configuration.";
}else{
  if(current_configuration !~ "ntp-service\s+access" && current_configuration !~ "ntp\s+access"){
    compliant = "no";
    value = "Disabled";
    comment = "'ntp-service access' or 'ntp access' not found in current-configuration.";
  }else{
    compliant = "yes";
    value = "Enabled";
    comment = "'ntp-service access' or 'ntp access' found in current-configuration.";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
