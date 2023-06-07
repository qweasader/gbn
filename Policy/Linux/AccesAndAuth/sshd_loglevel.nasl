# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.150067");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-01-14 14:14:36 +0100 (Tue, 14 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH LogLevel");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"INFO;QUIET;FATAL;ERROR;VERBOSE;DEBUG;DEBUG1;DEBUG2;DEBUG3", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.2.5 Ensure SSH LogLevel is appropriate (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 5.2.5 Ensure SSH LogLevel is appropriate (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.2 Activate audit logging");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 6.3 Enable Detailed Logging");

  script_tag(name:"summary", value:"INFO level is the basic level that only records login activity of SSH users.
  In many situations, such as Incident Response, it is important to determine when a particular user
  was active on a system. The logout record can eliminate those users who disconnected, which helps
  narrow the field.

  VERBOSE level specifies that login and logout activity as well as the key fingerprint for any SSH
  key used for login will be logged. This information is important for SSH key management,
  especially in legacy environments.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^LogLevel' /etc/ssh/sshd_config";
title = "SSH LogLevel";
solution = "Edit the /etc/ssh/sshd_config file to set the parameter as follows:

LogLevel VERBOSE

OR

LogLevel INFO

Note: This check will pass for the configuration set in the VT preferences unless configured
otherwise (default: INFO).";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/loglevel");
  compliant = policy_setting_exact_match(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
