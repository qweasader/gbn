# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900526");
  script_version("2021-09-01T14:04:04+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("XAMPP Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of XAMPP.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

if( ! http_can_host_php( port:port ) )
  exit( 0 );

dir = "/xampp";
version = "unknown";

url = dir + "/index.php";
res = http_get_cache( item:url, port:port );

if( "<title>XAMPP" >< res && "start.php" >< res ) {

  installed = TRUE;
  install = dir;
  vers = eregmatch( pattern:"<title>XAMPP (Version )?([0-9.]+)", string:res );
  if( ! isnull ( vers[2] ) )
    version = vers[2];

  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
}

if( ! installed || version == "unknown" ) {

  url = dir + "/start.php";
  res = http_get_cache( item:url, port:port );

  if( "<h1>Welcome to XAMPP" >< res || "and all other friends of XAMPP!<p>" >< res ||
      "You successfully installed XAMPP on this system!" >< res ) {
    installed = TRUE;
    install = dir;
    vers = eregmatch( pattern:"XAMPP.*Version ([0-9.]+)", string:res );
    if( ! isnull ( vers[1] ) )
      version = vers[1];

    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( ! installed || version == "unknown" ) {

  # Location for the newer 5.6.x versions
  url = "/dashboard";
  install = url;
  res = http_get_cache( item:url + "/", port:port );

  if( "<h1>Welcome to XAMPP" >< res || "You have successfully installed XAMPP on this system!" >< res ) {
    installed = TRUE;
    vers = eregmatch( pattern:"<h2>Welcome to XAMPP.* ([0-9.]+)</h2>", string:res );
    if( ! isnull ( vers[1] ) )
      version = vers[1];

    conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( installed ) {

  set_kb_item( name:"xampp/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apachefriends:xampp:" );
  if( ! cpe )
    cpe = "cpe:/a:apachefriends:xampp";

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"XAMPP",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
               port:port );
}

exit( 0 );
