###############################################################################
# OpenVAS Vulnerability Test
#
# GPON Home Router Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113169");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-05-03 16:40:00 +0200 (Thu, 03 May 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GPON Home Router Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 81, 443, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"GPON Home Router Detection.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 8080 );

res = http_get_cache( port: port, item: "/login.html" );
res2 = http_get_cache( port: port, item: "/" );

if( res =~ '<form id="XForm" name="XForm" method="post" action="/GponForm/LoginForm">' ||
    res =~ 'var XOntName = \'GPON Home Gateway\';' ||
    ( res2 =~ "^HTTP/1\.[01] 200" &&
        # nb: Both have line breaks in between
      ( res2 =~ "<title>.*GPON Home Gateway.*</title>" ||
        res2 =~ "<td colspan.*GPON Home Gateway.*</td>" )
    )
  ) {

  set_kb_item( name: "gpon/home_router/detected", value: TRUE );

  cpe = "cpe:/o:gpon:home_router_firmware";

  os_register_and_report( os: "GPON Home Router Firmware", cpe: cpe, desc: "GPON Home Router Detection", runs_key: "unixoide" );

  register_and_report_cpe( app: "GPON Home Router",
                           cpename: cpe,
                           insloc: "/",
                           regService: "www",
                           regPort: port );
}

exit( 0 );
