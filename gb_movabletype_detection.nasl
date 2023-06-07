# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113643");
  script_version("2021-11-01T10:00:52+0000");
  script_tag(name:"last_modification", value:"2021-11-01 10:00:52 +0000 (Mon, 01 Nov 2021)");
  script_tag(name:"creation_date", value:"2020-02-20 16:55:55 +0100 (Thu, 20 Feb 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Movable Type Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Movable Type.");

  script_xref(name:"URL", value:"https://www.movabletype.com/");

  exit(0);
}

CPE = "cpe:/a:sixapart:movabletype:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";

  buf = http_get_cache( port: port, item: url );

  if( buf !~ '<meta name="generator" content="Movable Type' &&
      ( buf !~ '>Powered by Movable Type' && ">Movable Type" >!< buf ) &&
      "p>Welcome to Movable Type, the professional publishing platform" >!< buf )
    continue;

  set_kb_item( name: "sixapart/movabletype/detected", value: TRUE );
  set_kb_item( name: "sixapart/movabletype/http/detected", value: TRUE );

  version = "unknown";
  beta = "";

  ver = eregmatch( pattern: '<meta name="generator" content="Movable Type( Publishing Platform| Pro)? ([0-9.]+)-?(beta[0-9-]+)?', string: buf, icase: TRUE );
  if( ! isnull( ver[2] ) ) {
    version = ver[2];
    if( ! isnull( ver[3] ) ) {
      beta = ver[3];
    }
  }
  else {
    ver = eregmatch( pattern: '>Powered by Movable Type( Publishing Platform| Pro)? ([0-9.]+)-?(beta[0-9-]+)?', string: buf, icase: TRUE );
    if( ! isnull( ver[2] ) ) {
      version = ver[2];
      if( ! isnull( ver[3] ) ) {
        beta = ver[3];
      }
    }
  }

  if( beta != "" ) {
    beta = ereg_replace( string: beta, pattern: "-", replace: "." );
    version += "-" + beta;
  }

  register_and_report_cpe( app: "Movable Type",
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: '([0-9.]+)-?(beta[0-9.]+)?',
                           insloc: install,
                           regPort: port,
                           regService: "www",
                           conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );

  exit( 0 );
}

exit( 0 );
