###############################################################################
# OpenVAS Vulnerability Test
#
# Sensiolabs Symfony Detection (Linux/Unix SSH Login)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107324");
  script_version("2021-06-15T12:39:35+0000");
  script_tag(name:"last_modification", value:"2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-06-26 16:20:53 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sensiolabs Symfony Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of a Sensiolabs Symfony.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

port = kb_ssh_transport();

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

path_list = ssh_find_file( file_name:"/Symfony/Component/HttpKernel/Kernel\.php$", useregex:TRUE, sock:sock );
if( ! path_list ) {
  ssh_close_connection();
  exit( 0 );
}

foreach path( path_list ) {

  path = chomp( path );
  if( ! path )
    continue;

  version_text = ssh_cmd( cmd:"grep 'This file is part of the Symfony package' " + path + " && grep 'const VERSION = ' " + path, socket:sock );
  if( ! version_text || "* This file is part of the Symfony package." >!< version_text ) # Safeguard if the command is echoed back in the response
    continue;

  # e.g.
  # const VERSION = '2.8.7';
  # const VERSION = '5.3.0-DEV';
  vers = eregmatch( string:version_text, pattern:"\s+const VERSION = '([0-9.]{3,})" );
  if( ! isnull( vers[1] ) ) {
    version_text = ereg_replace( string:version_text, pattern:'(\r\n)+', replace:"<newline>" );
    version = vers[1];
    location = str_replace( string:path, find:"/Component/HttpKernel/Kernel.php", replace:"" );
    found = TRUE;
    set_kb_item( name:"symfony/ssh-login/" + port + "/installs", value:"0#---#" + location + "#---#" + version + "#---#" + version_text + "#---#" + path );
  }
}

if( found ) {
  set_kb_item( name:"symfony/detected", value:TRUE );
  set_kb_item( name:"symfony/ssh-login/detected", value:TRUE );
  set_kb_item( name:"symfony/ssh-login/port", value:port );
}

exit( 0 );
