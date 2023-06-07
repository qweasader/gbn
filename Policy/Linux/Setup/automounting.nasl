# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.109730");
  script_version("2022-08-31T10:10:28+0000");
  script_tag(name:"last_modification", value:"2022-08-31 10:10:28 +0000 (Wed, 31 Aug 2022)");
  script_tag(name:"creation_date", value:"2019-01-09 08:27:42 +0100 (Wed, 09 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Status of automounting");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl", "linux_parse_chkconfig.nasl", "read_and_parse_systemctl_list_units.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_add_preference(name:"Automounting", type:"radio", value:"Disabled;Enabled", id:1);
  script_xref(name:"URL", value:"https://linux.die.net/man/5/autofs");

  script_xref(name:"Policy", value:"CIS Distribution Independent Linux v2.0.0: 1.1.22 Disable Automounting (Scored)");
  script_xref(name:"Policy", value:"CIS CentOS Linux 8 Benchmark v1.0.0: 1.1.22 Disable Automounting (Scored)");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.5 Configure Devices Not To Auto-run Content");
  script_xref(name:"Policy", value:"CIS Controls Version 7: 8.4 Configure Anti-Malware Scanning of Removable Devices");

  script_tag(name:"summary", value:"autofs allows automatic mounting of devices, typically including
CD/DVDs and USB drives.

With automounting enabled anyone with physical access could attach a USB drive or disc
and have its contents available in system even if they lacked permissions to mount it
themselves.");

  exit(0);
}

include( "ssh_func.inc" );
include( "policy_functions.inc" );
include( "list_array_func.inc" );

cmd = "systemctl is-enabled autofs; chkconfig --list autofs; ls /etc/rc*.d | grep autofs";
title = "Disable Automounting";
solution = "Run one of the following commands: 'chkconfig autofs off', 'systemctl disable autofs' or 'update-rc.d autofs disable'";
test_type = "SSH_Cmd";
default = script_get_preference( "Automounting", id:1 );

if( ! get_kb_item( "login/SSH/success" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not login to the host.";
} else if( get_kb_item( "Policy/linux/systemctl/ssh/ERROR" ) ||
           get_kb_item( "policy/linux/chkconfig/ssh/ERROR" ) ) {
  value = "Error";
  compliant = "incomplete";
  comment = "Can not run 'systemctl' or 'chkconfig' command due to SSH error.";
} else {
  if( get_kb_item( "Policy/linux/systemctl/autofs/service" ) == "enabled" ) {
    value = "Enabled";
    comment = "Detected with command 'systemctl is-enabled autofs'";
  } else if( chkconfig = get_kb_list( "policy/linux/chkconfig/autofs/*" ) ) {
    if( in_array( search:"on", array:chkconfig, part_match:FALSE ) ) {
      value = "Enabled";
      comment = "Detected with command 'chkconfig --list autofs'";
    }
  } else {
    if( ! sock = ssh_login_or_reuse_connection() ) {
      value = "Error";
      compliant = "incomplete";
      comment = "No SSH connection to host";
    } else {
      ls_cmd = "ls /etc/rc*.d | grep autofs";
      ls_return = ssh_cmd( socket:sock, cmd:ls_cmd, return_errors:FALSE );
      ls = egrep( string:ls_return, pattern:'^S' );

      if( ls ) {
        value = "Enabled";
        comment = "Detected with command 'ls /etc/rc*.d | grep autofs'";
      }
    }
  }

  if( ! value ) {
    value = "Disabled";
  }

  compliant = policy_setting_exact_match( value:value, set_point:default );
}

policy_reporting( result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment );

policy_set_kbs( type:test_type, cmd:cmd, default:default, solution:solution, title:title,
  value:value, compliant:compliant );

exit( 0 );
