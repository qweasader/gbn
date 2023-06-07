###############################################################################
# OpenVAS Vulnerability Test
#
# Netwave IP Camera Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.113253");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-08-28 11:35:00 +0200 (Tue, 28 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Netwave IP Camera Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects whether the target is a Netwave IP camera
  and if so, tries to gather information about firmware and software version-");

  script_xref(name:"URL", value:"http://www.netwavesystems.com/");

  exit(0);
}

CPE = "cpe:/h:netwave:ip_camera:";

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 80 );

foreach location ( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  url = location;
  if( url == "/" )
    url = "";

  # Using default Accept Header or User-Agent will result in an empty response.
  req = http_get_req( port: port, url: location, accept_header: '*/*',
   user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.98 Safari/537.36', host_header_use_ip: TRUE );
  buf = http_keepalive_send_recv( data: req, port: port );
  if( buf =~ 'Server: Netwave IP Camera' ) {
    set_kb_item( name: "netwave/ip_camera/detected", value: TRUE );
    set_kb_item( name: "netwave/ip_camera/port", value: port );

    info_url = url + "/get_status.cgi";
    req = http_get_req( port: port, url: info_url, accept_header: '*/*', host_header_use_ip: TRUE,
      user_agent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.98 Safari/537.36' );
    buf = http_keepalive_send_recv( data: req, port: port );
    version = "unknown";
    vers = eregmatch( string: buf, pattern: 'sys_ver[ ]?=[ ]?["\']([0-9.]+)["\']' );
    if( ! isnull( vers[1] ) ) {
      set_kb_item( name: "netwave/ip_camera/firmware_version", value: vers[1] );
      version = vers[1];
    }
    app_vers = eregmatch( string: buf, pattern: 'app_ver[ ]?=[ ]?["\']([0-9.]+)["\']' );
    if( ! isnull( app_vers[1] ) ) {
      set_kb_item( name: "netwave/ip_camera/app_version", value: app_vers[1] );
      extra = "App-Version: " + app_vers[1];
      extra += '\r\nConcluded from: ' + app_vers[0];
    }

    register_and_report_cpe( app: "Netwave IP Camera",
                             ver: version,
                             concluded: vers[0],
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: location,
                             regPort: port,
                             conclUrl: info_url,
                             extra: extra );

    exit( 0 );
  }
}
exit( 0 );
