# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105525");
  script_version("2023-01-10T10:12:01+0000");
  script_tag(name:"last_modification", value:"2023-01-10 10:12:01 +0000 (Tue, 10 Jan 2023)");
  script_tag(name:"creation_date", value:"2016-01-22 13:42:01 +0100 (Fri, 22 Jan 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Linux Host Information (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl", "os_detection.nasl");
  script_mandatory_keys("login/SSH/success", "Host/runs_unixoide");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based gathering of some information like the 'uptime'
  from a Linux host.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! sock = ssh_login_or_reuse_connection( ) )
  exit( 0 );

uptime = ssh_cmd( socket:sock, cmd:"cat /proc/uptime" );

if( uptime && uptime =~ "^[0-9]+\.[0-9]+" ) {

  now = unixtime();

  ut = split( uptime, sep:".", keep:FALSE );
  uptime = int( ut[0] );

  t_now = ( now - uptime );

  register_host_detail( name:"uptime", value:t_now );
  set_kb_item( name:"Host/uptime", value:t_now );
}

uname = get_kb_item( "Host/uname" );

if( uname && "Linux" >< uname ) {

  un = split( uname );
  foreach line( un ) {

    if( line =~ "^Linux" ) {

      # Linux $hostname 6.0.0-6-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.0.12-1 (2022-12-09) x86_64 GNU/Linux
      # Linux $hostname 4.19.46 #1-NixOS SMP Sat May 25 16:23:48 UTC 2019 x86_64 GNU/Linux
      # Linux $hostname 4.19.0-5-amd64 #1 SMP Debian 4.19.37-3 (2019-05-15) x86_64 GNU/Linux
      kv = eregmatch( pattern:"^Linux [^ ]+ ([^ ]+) #([0-9])+", string:line );

      if( ! isnull( kv[1] ) ) {
        set_kb_item( name:"Host/running_kernel_version", value:kv[1] );
        register_host_detail( name:"Running-Kernel", value:kv[1] );
      }

      if( ! isnull( kv[2] ) )
        set_kb_item( name:"Host/running_kernel_build_version", value:kv[2] );

      break;
    }
  }
}

close( sock );

exit( 0 );
