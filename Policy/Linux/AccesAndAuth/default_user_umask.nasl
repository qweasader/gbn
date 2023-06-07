# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109806");
  script_version("2021-05-18T12:49:08+0000");
  script_tag(name:"last_modification", value:"2021-05-18 12:49:08 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2019-03-12 14:21:23 +0100 (Tue, 12 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Default user umask");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_bash_profiles.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Default umask", type:"entry", value:"027", id:1);

  script_xref(name:"URL", value:"https://www.linuxnix.com/umask-define-linuxunix/");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.4.4 Ensure default user umask is 027 or more restrictive (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 5.5.5 Ensure default user umask is 027 or more restrictive (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 5.1 Establish Secure Configurations");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 13 Data Protection");

  script_tag(name:"summary", value:"User Mask (or User file creation MASK, umask) is the default
permission for a new file or directory created by a user.
Secure default permission prevents other users from accessing private data.
This script test for umask parameter set in files '/etc/bashrc', '/etc/bash.bashrc', '/etc/profile'
and '/etc/profile.d/*.sh");

  exit(0);
}

include("misc_func.inc");
include("policy_functions.inc");

cmd = "grep 'umask' /etc/bashrc /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh";
title = "Default user umask";
solution = "Edit files and add or modify 'umask MASK' parameter";
test_type = "SSH_Cmd";
default = script_get_preference("Default umask", id:1);

if(get_kb_item("Policy/linux/shell_initialization/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read bash profiles";
}else{
  kb_list = get_kb_list("Policy/linux/shell_initialization/*");
  foreach key (keys(kb_list)){
    if(key =~ ".+/ERROR$")
      continue;

    umask_line = egrep(pattern:"^\s*umask\s+[0-9]+", string:kb_list[key]);
    if(umask_line){
      umask_match = eregmatch(string:chomp(umask_line), pattern:"umask\s+([0-9]+)$");
      if(umask_match){
        umask = umask_match[1];
        comment +=  ", " + str_replace(string:key, find:"Policy/linux/shell_initialization", replace:"") + ": " + umask;
        if(policy_access_permissions_match_or_stricter(value:umask, set_point:default) != "no" &&
           umask != default){ # umask is stricter, if more permissions set. Therefore the logic is reversed.
          compliant = "no";
          value += ", " + str_replace(string:key, find:"Policy/linux/shell_initialization", replace:"") + ": " + umask;
        }
      }
    }
  }

  if(value){
    value = str_replace(string:value, find:", ", replace:"", count:1);
  }else if(comment){
    value = default;
    compliant = "yes";
  }else{
    value = "None";
    compliant = "incomplete";
    comment = "Can not find 'umask' in any shell initialization file.";
  }

  if(!compliant)
    compliant = "yes";

  comment = str_replace(string:comment, find:", ", replace:"", count:1);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);