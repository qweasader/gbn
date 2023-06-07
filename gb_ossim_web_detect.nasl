###############################################################################
# OpenVAS Vulnerability Test
#
# AlienVault OSSIM/USM Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100543");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-03-19 11:14:17 +0100 (Fri, 19 Mar 2010)");
  script_name("AlienVault OSSIM Detection");

  script_tag(name:"summary", value:"Detects the installed version of AlienVault OSSIM (Open Source Security
  Information Management) and USM (Unified Security Management)

  This script sends an HTTP GET request and tries to get the version from the response.");

  script_xref(name:"URL", value:"http://www.alienvault.com");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

if( ! http_can_host_php( port:port ) ) exit( 0 );

foreach dir (make_list_unique( "/ossim", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/session/login.php";

  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly: TRUE );

  if( egrep( pattern: "<title> AlienVault.*Open Source (SIM|SIEM)", string: buf, icase: FALSE ) ||
      egrep( pattern: "<title> OSSIM Framework Login", string: buf, icase: FALSE ) ||
      buf =~ "<title>AlienVault (USM|OSSIM)") {
    if (buf =~ "<title>AlienVault USM") {
      model = "USM";
      cpe = 'cpe:/a:alienvault:unified_security_management';
    } else {
      model = "OSSIM";
      cpe = 'cpe:/a:alienvault:open_source_security_information_management';
    }

    vers = "unknown";

    set_kb_item(name: "OSSIM/installed", value: TRUE);

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data: build_detection_report( app: "AlienVault " + model,
                                               version: vers,
                                               install: install,
                                               cpe: cpe,
                                               concluded: vers ),
                                               port: port );
  }
}

exit( 0 );
