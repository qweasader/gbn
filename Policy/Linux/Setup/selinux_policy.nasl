# Copyright (C) 2019 Greenbone Networks GmbH
#
# Text descriptions are largely excerpted from the referenced
# website, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.109741");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-01-16 08:27:48 +0100 (Wed, 16 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: SELinux policy configuration");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_selinux_config.nasl");
  script_mandatory_keys("Compliance/Launch");
  script_add_preference(name:"Policy configuration", type:"entry", value:"targeted", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/selinux");

  script_tag(name:"summary", value:"Security Enhanced Linux (SELinux) use the Linux Security Modules
and provides Mandatory Access Control (MAC). A MAC kernel protects the system from malicious apps.
The SELinux policy is a set of rules that guide SELinux. The default targeted policy constraints
daemons and system software only.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'SELINUXTYPE' /etc/selinux/config";
title = "SELinux Policy";
solution = "Add 'SELINUX=[targeted|strict]' to /etc/selinux/conf";
test_type = "SSH_Cmd";
default = script_get_preference("Policy configuration", id:1);

if(get_kb_item("Policy/linux//etc/selinux/config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/selinux/config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/selinux/config";
}else{
  content = get_kb_item("Policy/linux//etc/selinux/config/content");
  grep = egrep(string:content, pattern:"SELINUXTYPE\=");

  foreach line (split(grep)){
    if(line =~ "^\s*#")
      continue;

    match = eregmatch(string:chomp(line), pattern:"SELINUXTYPE=(.+)");
    if(match)
      value = match[1];
  }

  if(!value)
    value = "None";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);