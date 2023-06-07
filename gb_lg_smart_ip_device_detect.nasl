###############################################################################
# OpenVAS Vulnerability Test
#
# LG Smart IP Device Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113270");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-09-18 11:50:00 +0200 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LG Smart IP Device Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection for LG Smart IP Devices.");

  script_xref(name:"URL", value:"https://www.lg.com/");

  exit(0);
}

CPE = "cpe:/h:lg:smart_ip:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 8081 );

foreach location( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  buf = http_get_cache( item: location, port: port );

  if( buf =~ '<title>LG Smart IP Device</title>' ) {
    set_kb_item( name: "lg/smart_ip/detected", value: TRUE );
    set_kb_item( name: "lg/smart_ip/port", value: port );
    set_kb_item( name: "lg/smart_ip/location", value: location );

    version = "unknown";

    # Version can only be acquired with valid credentials
    # For that, scripts/2018/lg/gb_lg_smart_ip_default_credentials.nasl might be of help

    register_and_report_cpe( app: "LG Smart IP Device",
                             base: CPE,
                             ver: version,
                             expr: '([0-9.]+)',
                             insloc: location,
                             regPort: port,
                             conclUrl: location );
    break;
  }
}

exit( 0 );
