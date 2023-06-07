###############################################################################
# OpenVAS Vulnerability Test
#
# NetIQ Access Manager Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105148");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-03-31T08:09:36+0000");
  script_tag(name:"last_modification", value:"2021-03-31 08:09:36 +0000 (Wed, 31 Mar 2021)");
  script_tag(name:"creation_date", value:"2014-12-19 14:59:27 +0100 (Fri, 19 Dec 2014)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Micro Focus / NetIQ Access Manager Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Micro Focus / NetIQ Access Manager.");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.microfocus.com/en-us/cyberres/identity-access-management/access-manager");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/nidp/app";
buf = http_get_cache( item:url, port:port );
# nb: Some host redirect to SSO which we still can detect if follow the redirect
if( buf =~ "^HTTP/1\.[01] 30[0-9]" ) {
  loc = http_extract_location_from_redirect( port:port, data:buf, current_dir:"/" );
  if( loc ) {
    url = loc;
    buf = http_get_cache( item:url, port:port );
  }
}

if( ! buf || ( buf !~ "<title>(NetIQ )?Access Manager" && "/nidp/app/login?id=" >!< buf &&
               "UrnNovellNidpClusterMemberId" >!< buf ) )
  exit( 0 );

set_kb_item( name:"netiq_access_manager/installed", value:TRUE);
version = "unknown";
version_url = "/nidp/html/help/en/bookinfo.html";

version_resp = http_get_cache( item:version_url, port:port );
# nb: This is just the major version
version_match = eregmatch( pattern:"Access Manager ([0-9.]+) User Portal Help", string:version_resp );

if( version_match[1] ) {
  version = version_match[1];
  concluded_url = http_report_vuln_url( port:port, url:version_url, url_only:TRUE);
}

cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microfocus:access_manager:" );
cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:netiq:access_manager:" );
if( ! cpe1 ) {
  cpe1 = "cpe:/a:microfocus:access_manager";
  cpe2 = "cpe:/a:netiq:access_manager";
}

register_product( cpe:cpe1, location:"/", port:port, service:"www" );
register_product( cpe:cpe2, location:"/", port:port, service:"www" );

log_message( data:build_detection_report( app:"Micro Focus / NetIQ Access Manager", version: version, cpe:cpe1,
                                          install:"/", concluded:version_match[0], concludedUrl:concluded_url ),
             port:port );

exit( 0 );
