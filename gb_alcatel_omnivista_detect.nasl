###############################################################################
# OpenVAS Vulnerability Test
#
# Alcatel-Lucent Omnivista Version Detection
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107113");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-12-22 06:40:16 +0200 (Thu, 22 Dec 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Alcatel-Lucent Omnivista Detection");

  script_tag(name:"summary", value:"Detection of Alcatel-Lucent Omnivista.

  The script sends a connection request to the server and attempts to detect Alcatel Lucent Omnivista.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.al-enterprise.com");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = '/';

res = http_get_cache( port:port, item:url );

if ( "<title>Alcatel-Lucent OmniVista" >!< res ) {
  url = "/login.html";
  res = http_get_cache( port:port, item:url );

  if ( "<title>OmniVista" >!< res || "OmniVistaApp" >!< res)
    exit(0);
}

version = "unknown";

mod = eregmatch( pattern:"OmniVista ([0-9]{4}) NMS", string:res );
if ( !isnull(mod[1]) )
  model = mod[1];

set_kb_item( name:"alcatel/omnivista/detected", value:TRUE );

if ( model )
  cpe = "cpe:/a:alcatel-lucent:omnivista_" + model;
else
  cpe = "cpe:/a:alcatel-lucent:omnivista";

register_product( cpe:cpe, location:"/", port:port, service:"www" );

log_message( data:build_detection_report( app:"Alcatel-Lucent Omnivista " + model, version:version, install:"/",
                                          cpe:cpe ),
             port:port );

exit(0);
