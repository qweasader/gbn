# Copyright (C) 2020 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.150081");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-01-16 09:19:53 +0100 (Thu, 16 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SSH AllowGroups");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"group1 group2", id:1); # legacy

  script_xref(name:"URL", value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.2.18 Ensure SSH access is limited (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 5.2.2 Ensure SSH access is limited (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 4.3 Ensure the Use of Dedicated Administrative Accounts");

  script_tag(name:"summary", value:"There are several options available to limit which users and group can access
  the system via SSH. It is recommended that at least one of the following options be leveraged:

  AllowUsers
  AllowGroups
  DenyUsers
  DenyGroups

  Note: The check reports the AllowGroups from the SSHD config file. Please check the compliance status manually.");

  exit(0);
}

include( "policy_functions.inc" );

cmd = "grep '^AllowGroups' /etc/ssh/sshd_config";
title = "SSH AllowGroups";
solution = "Edit /etc/ssh/sshd_config";
test_type = "Manual Check";
default = "None";
compliant = "incomplete";
comment = "Please check manually if the value match the local side policy.";

if( get_kb_item( "linux/mount/ERROR" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  allowgroups = get_kb_list( "Policy/linux/sshd_config/allowgroups" );
  if ( ! allowgroups || allowgroups == "" )
    value = "None";
  else
    value = policy_build_string_from_list( list:allowgroups, sep:", " );
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit(0);