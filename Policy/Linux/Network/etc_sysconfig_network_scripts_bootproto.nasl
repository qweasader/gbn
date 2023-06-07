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
  script_oid("1.3.6.1.4.1.25623.1.0.150183");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2020-03-25 10:25:06 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: BOOTPROTO in /etc/sysconfig/network-scripts/*");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "read_and_parse_nmcli.nasl", "read_etc_sysconfig_network_scripts.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Value", type:"radio", value:"none;dhcp;bootp;static", id:1);

  script_xref(name:"URL", value:"https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/networking_guide/sec-configuring_ip_networking_with_ifcg_files");
  script_xref(name:"URL", value:"http://www.tldp.org/LDP/solrhe/Securing-Optimizing-Linux-RH-Edition-v1.3/chap9sec90.html");

  script_tag(name:"summary", value:"Interface configuration (ifcfg) files control the software
interfaces for individual network devices. As the system boots, it uses these files to determine
what interfaces to bring up and how to configure them. These files are usually named ifcfg-name,
where the suffix name refers to the name of the device that the configuration file controls. By
convention, the ifcfg file's suffix is the same as the string given by the DEVICE directive in the
configuration file itself.

The BOOTPROTO setting is used to determine which protocol to use at boot time:

  - none: No boot-time protocol should be used

  - bootp: The bootp now pump protocol should be used

  - dhcp: The dhcp protocol should be used

  - static: Use static IP address");

  exit(0);
}

include("policy_functions.inc");

cmd = "grep BOOTPROTO /etc/sysconfig/network-scripts/*";
title = "BOOTPROTO in /etc/sysconfig/network-scripts/*";
solution = "Set BOOTPROTO=[none,dhcp,bootp,static] in network devices config files /etc/sysconfig/network-scripts/";
test_type = "SSH_Cmd";
default = script_get_preference("Value", id:1);

if(get_kb_item("Policy/linux/nmcli/ssh/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "No SSH connection to host";
}else if(get_kb_item("Policy/linux/nmcli/ERROR")){
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run nmcli";
}else{
  devices = get_kb_list("Policy/linux/nmcli/devices");

  foreach device (devices){
    kb_item = "Policy/linux//etc/sysconfig/network-scripts/ifcfg-" + device + "/content";
    if(!config = get_kb_item(kb_item))
      continue;

    grep = egrep(string:config, pattern:"BOOTPROTO", icase:TRUE);
    match = eregmatch(string:chomp(grep), pattern:'BOOTPROTO="?([a-zA-Z]+)');
    if(match){
      comment += ", " + device + ": " + match[1];
      if(policy_setting_exact_match(value:match[1], set_point:default) != "yes"){
        compliant = "no";
        value = match[1];
      }
    }
  }

  if(!comment){
    value = "None";
    compliant = "incomplete";
    comment = "Can not find BOOTPROTO setting in any config files in /etc/sysconfig/network-scripts";
  }else if(!value){
    value = default;
    compliant = "yes";
  }

  comment = str_replace(string:comment, find:", ", replace:"", count:1);
}

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);
policy_set_kbs(type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant);

exit(0);