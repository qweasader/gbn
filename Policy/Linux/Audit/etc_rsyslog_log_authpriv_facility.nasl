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
  script_oid("1.3.6.1.4.1.25623.1.0.150159");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-03-12 11:25:13 +0000 (Thu, 12 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: authpriv.* facility in /etc/rsyslog.conf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_etc_rsyslog_conf.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"/var/log/authlog", id:1);

  script_xref(name:"URL", value:"https://linux.die.net/man/5/rsyslog.conf");
  script_xref(name:"URL", value:"https://linux.die.net/man/3/syslog");

  script_tag(name:"summary", value:"The facility argument is used to specify what type of program is
logging the message. This lets the configuration file specify that messages from different
facilities will be handled differently.

  - LOG_AUTHPRIV: security/authorization messages (private).

The asterisk ('*') means log all priorities.");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep 'authpriv.*' /etc/rsyslog.conf";
title = "Log security / authorization messages (private) for all priorities to specified files";
solution = "Add 'authpriv.* FILE' to /etc/rsyslog.conf";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux//etc/rsyslog.conf/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux//etc/rsyslog.conf/content/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not read /etc/rsyslog.conf";
}else{
  content = get_kb_item("Policy/linux//etc/rsyslog.conf/content");
  grep = egrep(string:content, pattern:"authpriv\.\*");
  if(grep){
    foreach line (split(grep, keep:FALSE)){
      if(line =~ "^\s*#")
        continue;
      file = eregmatch(string:line, pattern:"[^\s]+\s+(.*)");
      if(file)
        value += "," + file[1];
    }
  }

  if(value)
    value = str_replace(string:value, find:",", replace:"", count:1);
  else
    value = "None";

  compliant = policy_settings_lists_match(value:value, set_points:default, sep:",");

}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);
