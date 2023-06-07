# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.150172");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-03-18 09:01:04 +0000 (Wed, 18 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: audtitd status");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_and_parse_systemctl_list_units.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/auditd");

  script_add_preference(name:"Value", type:"radio", value:"enabled;disabled;status;indirect", id:1);

  script_tag(name:"summary", value:"auditd is the userspace component to the Linux Auditing System.
It's responsible for writing audit records to the disk. Viewing the logs is done with the ausearch
or aureport utilities. Configuring the audit rules is done with the auditctl utility. During startup,
the rules in /etc/audit/audit.rules are read by auditctl. The audit daemon itself has some
configuration options that the admin may wish to customize. They are found in the auditd.conf file.");

  exit(0);
}

include("policy_functions.inc");

cmd = "systemctl is-enabled auditd";
title = "Status of auditd";
solution = "Run 'systemctl OPTION auditd";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/systemctl/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux/systemctl/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run systemctl";
}else{
  if(!value = get_kb_item("Policy/linux/systemctl/auditd/service"))
    value = "Not found";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
