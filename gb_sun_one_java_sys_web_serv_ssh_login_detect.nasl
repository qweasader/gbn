# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108502");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-12-08 13:32:46 +0100 (Sat, 08 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun Java System/ONE Web Server Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of the Sun Java System/ONE Web Server.");

  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

full_path_list = ssh_find_file( file_name:"/webservd$", useregex:TRUE, sock:sock );
foreach full_path( full_path_list ) {

  file = chomp( file );
  if( ! file )
    continue;

  vers = ssh_get_bin_version( full_prog_name:file, sock:sock, version_argv:"-v", ver_pattern:"Sun (ONE|Java System) Web Server ([0-9.]+)(SP|U)?([0-9]+)?([^0-9.]|$)" );

  if( ! isnull( vers[2] ) ) {
    if( ! isnull( vers[4] ) )
      version = vers[2] + "." + vers[4];
    else
      version = vers[2];

    if( vers[1] == "ONE" ) {
      set_kb_item( name:"sun/one_web_server/detected", value:TRUE );
      set_kb_item( name:"sun/one_web_server/ssh-login/detected", value:TRUE );
      cpe_base = "cpe:/a:sun:one_web_server:";
      app_name = "Sun ONE Web Server";
    } else {
      set_kb_item( name:"sun/java_system_web_server/detected", value:TRUE );
      set_kb_item( name:"sun/java_system_web_server/ssh-login/detected", value:TRUE );
      cpe_base = "cpe:/a:sun:java_system_web_server:";
      app_name = "Sun Java System Web Server";
    }

    # Generic KB key for VTs which are covering e.g. both products
    set_kb_item( name:"oracle_or_sun/web_server/detected", value:TRUE );
    set_kb_item( name:"oracle_or_sun/web_server/ssh-login/detected", value:TRUE );

    register_and_report_cpe( app:app_name, ver:version, base:cpe_base, expr:"([0-9.]+)", regPort:0, insloc:file, concluded:vers[0], regService:"ssh-login" );
  }
}

ssh_close_connection();
exit( 0 );