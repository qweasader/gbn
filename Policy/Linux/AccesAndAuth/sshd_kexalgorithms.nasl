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
  script_oid("1.3.6.1.4.1.25623.1.0.150077");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-02-26 11:48:15 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: KexAlgorithms");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_sshd_config.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"entry", value:"curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256", id:1);

  script_xref(name:"URL",value:"https://linux.die.net/man/5/sshd_config");
  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 14.4 Encrypt All Sensitive Information in Transit");

  script_tag(name:"summary", value:"Key exchange is any method in cryptography by which cryptographic keys are
  exchanged between two parties, allowing use of a cryptographic algorithm. If the sender and
  receiver wish to exchange encrypted messages, each must be equipped to encrypt messages to be sent
  and decrypt messages received.

  Note: This check fails if any KexAlgorithms are found that are not specified in the VT preferences.");

  exit(0);
}

include("ssh_func.inc");
include("policy_functions.inc");

cmd = "grep '^KexAlgorithms' /etc/ssh/sshd_config";
title = "SSH KexAlgorithms";
solution = "Edit /etc/ssh/sshd_config";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/sshd_config/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Could not read /etc/ssh/sshd_config";
}else{
  value = get_kb_item("Policy/linux/sshd_config/kexalgorithms");
  if(!value){
    value = "Error";
    compliant = "incomplete";
    comment = "Unable to retrieve supported KexAlgorithms from /etc/ssh/sshd_config";
  }else{
    compliant = "yes";

    foreach kexalgorithm(policy_build_list_from_string(str:value)){
      if(kexalgorithm >!< default)
        compliant = "no";
    }
  }
}

policy_reporting(result:value,default:default,compliant:compliant,fixtext:solution,
  type:test_type,test:cmd,info:comment);
policy_set_kbs(type:test_type,cmd:cmd,default:default,solution:solution,title:title,
  value:value,compliant:compliant);

exit(0);
