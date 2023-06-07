# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800598");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Avast Antivirus Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script detects the installed version of Avast Antivirus.");
  exit(0);
}

include("ssh_func.inc");
include("cpe.inc");
include("host_details.inc");

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

getPaths = ssh_find_file( file_name:"/avast$", useregex:TRUE, sock:sock );
foreach binaryFile( getPaths ) {

  binaryFile = chomp( binaryFile );
  if( ! binaryFile )
    continue;

  vers = ssh_get_bin_version( full_prog_name:binaryFile, version_argv:"-V", ver_pattern:"avast v([0-9.]+)", sock:sock );
  if( vers[1] != NULL ) {
    version = vers[1];
    set_kb_item( name:"avast/antivirus/detected", value:TRUE );
    log_message(data:"Avast Antivirus version " + vers[1] + " running at location " + binaryFile +  " was detected on the host");
    ssh_close_connection();

    register_and_report_cpe( app:"Avast Antivirus", ver:version,
                             base:"cpe:/a:avast:antivirus:", expr:"^([0-9.]+)", insloc:binaryFile,
                             regService:"ssh-login", regPort:0 );
    exit( 0 );
  }
}
ssh_close_connection();
exit( 0 );
