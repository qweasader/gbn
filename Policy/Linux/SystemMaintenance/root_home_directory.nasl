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
  script_oid("1.3.6.1.4.1.25623.1.0.150107");
  script_version("2020-07-29T09:51:47+0000");
  script_tag(name:"last_modification", value:"2020-07-29 09:51:47 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 10:27:51 +0100 (Wed, 29 Jan 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Home directory for root user");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("read_passwd_file.nasl", "compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"/root", id:1);

  script_tag(name:"summary", value:"The password file stores information about users such like
username, UID, GID, etc.

This script tests, if home directories for users are located in /home.");

  exit(0);
}

include("policy_functions.inc");

cmd = "cat /etc/passwd";
title = "Home directory for root user";
solution = "usermod -d /DIR root";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(!get_kb_item("login/SSH/success")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection";
}else if(get_kb_item("Policy/linux//etc/passwd/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/passwd";
}else{
  passwd_content = get_kb_item("Policy/linux//etc/passwd/content");
  foreach line (split(passwd_content, keep:FALSE)){
    entries = split(line, sep:":", keep:FALSE);
    user = entries[0];
    if(user == "root"){
      value = entries[5];
      compliant = policy_setting_exact_match(value:value, set_point:default);
    }
  }

  if(!value){
    value = "Error";
    compliant = "no";
    comment = "Did not find user root in /etc/passwd";
  }
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);