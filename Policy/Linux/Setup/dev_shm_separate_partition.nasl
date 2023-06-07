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
  script_oid("1.3.6.1.4.1.25623.1.0.150058");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-01-10 10:33:06 +0100 (Fri, 10 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Separate partition for /dev/shm");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "linux_list_mounted_filesystems.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Separate partition", type:"radio", value:"yes;no", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/8/mount");

  script_tag(name:"summary", value:"/dev/shm implements traditional shared memory concept. It is an
efficient means of passing data between programs.

This script tests if a separate partition exists for /dev/shm.");
  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");
include("misc_func.inc");
include("list_array_func.inc");

cmd = "mount | grep /dev/shm";
title = "Separate partition for /dev/shm";
solution = "Create a new partition and configure /dev/shm as appropriate";
test_type = "SSH_Cmd";
default = script_get_preference("Separate partition", id:1);

if(get_kb_item("linux/mount/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not get information about mounted partitions";
}else{
  mounted_partitions = get_kb_list("linux/mount/device");
  if(!in_array(search:"/dev/shm", array:mounted_partitions, part_match:FALSE))
    value = "no";
  else
    value = "yes";
  compliant = policy_setting_exact_match(value:value, set_point:default);
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
