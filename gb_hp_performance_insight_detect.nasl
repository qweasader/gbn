###############################################################################
# OpenVAS Vulnerability Test
#
# HP Performance Insight Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103059");
  script_version("2021-09-07T06:04:54+0000");
  script_tag(name:"last_modification", value:"2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)");
  script_tag(name:"creation_date", value:"2011-02-03 16:40:04 +0100 (Thu, 03 Feb 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HP OpenView Performance Insight Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&cp=1-11-15-119^1211_4000_100__");

  script_tag(name:"summary", value:"This host is running the HP OpenView Performance Insight Web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("cpe.inc");

port = http_get_port( default:8080 );

buf = http_get_cache( item:"/", port:port );
if( ! buf )
  exit( 0 );

if( ( "<h1>HP Performance Insight" >< buf || "HP OpenView Performance Insight Login" >< buf ) && "Hewlett-Packard" >< buf ) {

  install = "/";
  vers = "unknown";

  version = eregmatch( string:buf, pattern:"<h4>Version ([^<]+)<", icase:TRUE );
  if( ! isnull( version[1] ) ) vers = chomp( version[1] );

  set_kb_item( name:"hp/openview_performance_insight/detected", value:TRUE );

  cpe = build_cpe( value:vers, exp:"([0-9.]+)", base:"cpe:/a:hp:openview_performance_insight:");
  if( ! cpe )
    cpe = "cpe:/a:hp:openview_performance_insight";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"HP OpenView Performance Insight",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0] ),
                                            port:port );
}

exit( 0 );
