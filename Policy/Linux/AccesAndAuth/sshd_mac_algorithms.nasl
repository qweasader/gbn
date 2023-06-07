# Copyright (C) 2019 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License,or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not,write to the Free Software
# Foundation,Inc.,51 Franklin St,Fifth Floor,Boston,MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.109795");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-02-26 11:48:15 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: MAC algorithms");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"MAC algorithms", type:"entry", value:"hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256", id:1);

  script_xref(name:"URL",value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.2.14 Ensure only strong MAC algorithms are used (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 14.4 Encrypt All Sensitive Information in Transit");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 16.5 Encrypt Transmittal of Username and Authentication Credentials");

  script_tag(name:"summary", value:"This variable limits the types of MAC algorithms that SSH can use during
  communication. MD5 and 96-bit MAC algorithms are considered weak and have been shown to increase
  exploitability in SSH downgrade attacks. Weak algorithms continue to have a great deal of
  attention as a weak spot that can be exploited with expanded computing power. An attacker that
  breaks the algorithm could take advantage of a MiTM position to decrypt the SSH tunnel and capture
  credentials and information.

  Note: This check fails if any MAC algorithms are found that are not specified in the VT preferences.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^MACs' /etc/ssh/sshd_config";
title = "SSH MAC algorithms";
solution = "Edit the /etc/ssh/sshd_config file and add/modify the MACs line to contain a comma separated
list of the site approved MACs

Example:

MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256";
test_type = "SSH_Cmd";
default = script_get_preference("MAC algorithms", id:1);

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/macs");
  if(!value){
    value = "Error";
    compliant = "incomplete";
    comment = "Could not retrieve supported MAC algorithms from /etc/ssh/sshd_config";
  }else{
    compliant = "yes";

    foreach mac(policy_build_list_from_string(str:value)){
      if(mac >!< default)
        compliant = "no";
    }
  }
}
policy_reporting(result:value,default:default,compliant:compliant,fixtext:solution,
  type:test_type,test:cmd,info:comment);
policy_set_kbs(type:test_type,cmd:cmd,default:default,solution:solution,title:title,
  value:value,compliant:compliant);

exit(0);
