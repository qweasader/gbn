# Copyright (C) 2020 Greenbone Networks GmbH
#
# Text descriptions are largely excerpted from the referenced
# website, and are Copyright (C) of their respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.150126");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-02-04 15:23:37 +0100 (Tue, 04 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: /etc/login.defs LOG_UNKFAIL_ENAB");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_login_defs.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"Yes;No", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/login.defs");

  script_tag(name:"summary", value:"The /etc/login.defs file defines the site-specific configuration
for the shadow password suite. This file is required. Absence of this file will not prevent system
operation, but will probably result in undesirable operation.

LOG_UNKFAIL_ENAB (boolean) enables display of unknown usernames when login failures are recorded.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep '^LOG_UNKFAIL_ENAB' /etc/login.defs";
title = "LOG_UNKFAIL_ENAB setting in /etc/login.defs";
solution = "Edit /etc/login.defs";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux//etc/login.defs/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not access host";
}else if(get_kb_item("Policy/linux//etc/login.defs/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/login.defs";
}else{
  etc_login_defs_content = get_kb_item("Policy/linux//etc/login.defs/content");
  line = egrep(string:etc_login_defs_content, pattern:"^\s*LOG_UNKFAIL_ENAB");
  if(line){
    value = eregmatch(string:line, pattern:"^\s*LOG_UNKFAIL_ENAB\s*(.*)");
    value = chomp(value[1]);
  }else{
    value = "None";
  }
  compliant = policy_setting_exact_match(value:tolower(value), set_point:tolower(default));
  comment = "";
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
