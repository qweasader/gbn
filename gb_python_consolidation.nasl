# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112857");
  script_version("2021-07-09T08:01:09+0000");
  script_tag(name:"last_modification", value:"2021-07-09 08:01:09 +0000 (Fri, 09 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-02-01 08:12:11 +0000 (Mon, 01 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Python Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_python_ssh_login_detect.nasl", "gb_python_http_detect.nasl", "gb_python_detect_macosx.nasl", "gb_python_detect_win.nasl");
  script_mandatory_keys("python/detected");

  script_xref(name:"URL", value:"https://www.python.org/");

  script_tag(name:"summary", value:"Consolidation of Python detections.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("cpe.inc");

if( ! get_kb_item( "python/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ssh-login", "smb-login", "http" ) ) {

  install_list = get_kb_list( "python/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclurl = infos[4];

    # Python 2.7.18
    # Python 3.10.0a2
    # Python 3.9.0b5
    # Python 3.8.7rc1
    # Python 3.9.1+
    # nb: Currently unclear what "+" above means...
    cpe = build_cpe( value:version, exp:"^([0-9a-z.]+)", base:"cpe:/a:python:python:" );
    if( ! cpe )
      cpe = "cpe:/a:python:python";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Python",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concludedUrl:conclurl,
                                      concluded:concl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );