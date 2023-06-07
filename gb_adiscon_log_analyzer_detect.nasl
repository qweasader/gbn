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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113315");
  script_version("2021-06-17T10:24:47+0000");
  script_tag(name:"last_modification", value:"2021-06-17 10:24:47 +0000 (Thu, 17 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-12-12 12:55:55 +0100 (Wed, 12 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Adiscon LogAnalyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Adiscon LogAnalyzer.");

  script_xref(name:"URL", value:"https://loganalyzer.adiscon.com/");

  exit(0);
}

CPE = "cpe:/a:adiscon:log_analyzer:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

if( ! http_can_host_php( port: port ) )
  exit( 0 );

foreach location( make_list_unique( "/", "/loganalyzer", http_cgi_dirs( port: port ) ) ) {
  dir = location;
  if( dir == "/" )
    dir = "";
  dir = dir + "/login.php";

  buf = http_get_cache( item: dir, port: port );

  if( buf =~ "<strong>Use this form to login into LogAnalyzer" || buf =~ "<title>Adiscon LogAnalyzer" ) {

    set_kb_item( name: "adiscon/log_analyzer/detected", value: TRUE );
    set_kb_item( name: "adiscon/log_analyzer/http/detected", value: TRUE );
    set_kb_item( name: "adiscon/log_analyzer/port", value: port );
    set_kb_item( name: "adiscon/log_analyzer/location", value: location );

    version = "unknown";

    ver = eregmatch( string: buf, pattern: "LogAnalyzer</A> Version ([0-9.]+)" );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      set_kb_item( name: "adiscon/log_analyzer/version", value: version );
    }

    register_and_report_cpe( app: "Adiscon LogAnalyzer",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: "([0-9.]+)",
                             insloc: location,
                             regPort: port,
                             conclUrl: dir );

    exit( 0 );
  }
}

exit( 0 );