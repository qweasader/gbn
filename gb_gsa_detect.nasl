# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103841");
  script_version("2022-08-11T10:10:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-11 10:10:35 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"creation_date", value:"2013-11-29 14:30:41 +0100 (Fri, 29 Nov 2013)");
  script_name("Greenbone Security Assistant (GSA) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 9392);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of the Greenbone Security Assistant
  (GSA).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("cpe.inc");

port = http_get_port( default:9392 );

url = "/login/login.html";
buf = http_get_cache( item:url, port:port );

if( buf && buf =~ "^HTTP/1\.[01] 200" && '<form action="/omp" method="' >< buf &&
    "Greenbone Security Assistant" >< buf ) {

  install = "/";
  vers    = "unknown";
  version = eregmatch( string:buf, pattern:'<span class="version">Version ([^<]+)</span>', icase:FALSE );
  if( ! isnull( version[1] ) )
    vers = version[1];

  set_kb_item( name:"greenbone_security_assistant/detected", value:TRUE );
  set_kb_item( name:"greenbone_security_assistant/pre80/detected", value:TRUE );
  set_kb_item( name:"greenbone_security_assistant/" + port + "/omp", value:TRUE ); # nb: for gb_gsa_admin_login.nasl to be able to choose the auth endpoint
  set_kb_item( name:"greenbone_security_assistant/" + port + "/version", value:vers );
  set_kb_item( name:"openvas_gvm/framework_component/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service doesn't support these
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"no" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"no" );

  cpe = build_cpe( value:vers, exp:"^([0-9.-]+)", base:"cpe:/a:greenbone:greenbone_security_assistant:" );
  if( ! cpe )
    cpe = "cpe:/a:greenbone:greenbone_security_assistant";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Greenbone Security Assistant (GSA) Detection (HTTP)", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Greenbone Security Assistant (GSA)",
                                            version:vers,
                                            concluded:version[0],
                                            install:install,
                                            cpe:cpe ),
               port:port );
  exit( 0 );
}

url = "/login";
buf = http_get_cache( item:url, port:port );

if( buf && buf =~ "^HTTP/1\.[01] 200" &&
    ( "<title>Greenbone Security Assistant</title>" >< buf || # nb: Plain GSA installation from sources
      "<title>Greenbone Security Manager</title>" >< buf || # nb: On GOS <= 21.04
      "<title>Greenbone Enterprise Appliance</title>" >< buf # nb: On GOS >= 22.04
    )
  ) {

  install = "/";
  vers    = "unknown";

  set_kb_item( name:"greenbone_security_assistant/detected", value:TRUE );
  set_kb_item( name:"greenbone_security_assistant/80plus/detected", value:TRUE );
  set_kb_item( name:"greenbone_security_assistant/" + port + "/gmp", value:TRUE ); # nb: for gb_gsa_admin_login.nasl to be able to choose the auth endpoint
  set_kb_item( name:"greenbone_security_assistant/" + port + "/version", value:vers );
  set_kb_item( name:"openvas_gvm/framework_component/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service doesn't support these
  replace_kb_item( name:"www/" + port + "/can_host_php", value:FALSE );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:FALSE );

  cpe = build_cpe( value:vers, exp:"^([0-9.-]+)", base:"cpe:/a:greenbone:greenbone_security_assistant:" );
  if( ! cpe )
    cpe = "cpe:/a:greenbone:greenbone_security_assistant";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  os_register_and_report( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", port:port, desc:"Greenbone Security Assistant (GSA) Detection (HTTP)", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Greenbone Security Assistant (GSA)",
                                            version:vers,
                                            install:install,
                                            cpe:cpe ),
               port:port );
}

exit( 0 );
