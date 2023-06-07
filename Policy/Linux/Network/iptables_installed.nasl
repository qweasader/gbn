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
  script_oid("1.3.6.1.4.1.25623.1.0.150179");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-03-24 10:05:37 +0000 (Tue, 24 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Install iptables");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "gather-package-list.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://linux.die.net/man/8/iptables");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 3.5.3 Ensure iptables is installed (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 9.4 Apply Host-based Firewalls or Port Filtering");

  script_tag(name:"summary", value:"Iptables is used to set up, maintain, and inspect the tables of
IP packet filter rules in the Linux kernel.");

  exit(0);
}

include("policy_functions.inc");

cmd = "[rpm -q, dpkg -s] iptables";
title = "Install iptables";
solution = "Install package 'iptables'";
test_type = "SSH_Cmd";
default = "Installed";

if(!get_kb_item("login/SSH/success")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else{
  iptables_installed = get_package_version(package:"iptables");
  if(!iptables_installed)
    value = "Not installed";
  else
    value = "Installed";

  compliant = policy_setting_exact_match(value:value, set_point:default);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
