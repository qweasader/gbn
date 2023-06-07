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
  script_oid("1.3.6.1.4.1.25623.1.0.100274");
  script_version("2021-10-11T11:24:48+0000");
  script_tag(name:"last_modification", value:"2021-10-11 11:24:48 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2009-10-01 18:57:31 +0200 (Thu, 01 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("nginx Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl",
                      "gb_nginx_http_error_page_detect.nasl", "gb_php_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't add a nginx/banner script_mandatory_keys because the VT is also doing a detection
  # based on a 404 error page.

  script_tag(name:"summary", value:"HTTP based detection of nginx.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );

banner = http_get_remote_headers( port:port );

vers = "unknown";

# Server: nginx/1.14.2
# Server: nginx/1.10.3
# Server: nginx
# Server: nginx/1.14.0 (Ubuntu)
if( banner && concl = egrep( pattern:"^Server\s*:\s*nginx", string:banner, icase:TRUE ) ) {

  concl = chomp( concl );
  detected = TRUE;

  version = eregmatch( string:banner, pattern:"Server\s*:\s*nginx/([0-9.]+)", icase:TRUE );
  if( ! isnull( version[1] ) ) {
    vers = version[1];
  } else {
    # Some configs are reporting the version in the banner if an index.php is called
    host = http_host_name( dont_add_port:TRUE );
    phpList = http_get_kb_file_extensions( port:port, host:host, ext:"php" );
    if( phpList )
      phpFiles = make_list( phpList );

    if( phpFiles[0] )
      url = phpFiles[0];
    else
      url = "/index.php";

    banner = http_get_remote_headers( port:port, file:url );

    version = eregmatch( string:banner, pattern:"Server\s*:\s*nginx/([0-9.]+)", icase:TRUE );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
      if( concl )
        concl += '\n';
      concl += version[0];

      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

if( ! detected || vers == "unknown" ) {

  # nb: From gb_nginx_http_error_page_detect.nasl. This has always either "Server: nginx"
  # or "Server: nginx/1.2.3" so no separate check needs to be done here.
  if( banner = get_kb_item( "www/nginx_error_page/banner/" + port ) ) {

    vers = "unknown";
    detected = TRUE;

    if( url = get_kb_item( "www/nginx_error_page/banner/location/" + port ) ) {
      if( conclUrl )
        conclUrl += '\n';
      conclUrl += http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( concluded = get_kb_item( "www/nginx_error_page/banner/concluded/" + port ) ) {
      if( concl )
        concl += '\n';
      concl += concluded;
    }

    version = eregmatch( pattern:"Server\s*:\s*nginx/([0-9.]+)", string:banner, icase:TRUE );
    if( ! isnull( version[1] ) ) {
      vers = version[1];
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: nginx/" + vers );
    } else {
      replace_kb_item( name:"www/real_banner/" + port + "/", value:"Server: nginx" );
    }
  }
}

if( detected ) {

  install = port + "/tcp";

  # Status page of the HttpStubStatusModule (https://nginx.org/en/docs/http/ngx_http_stub_status_module.html) module
  foreach ngnx_status( make_list( "/", "/basic_status", "/nginx_status", "/nginx-status" ) ) {
    res = http_get_cache( port:port, item:ngnx_status );
    if( res =~ "^HTTP/1\.[01] 200" &&
        ( egrep( string:res, pattern:"^Active connections: [0-9]+" ) || # Active connections: 4
          egrep( string:res, pattern:"^server accepts handled requests( request_time)?" ) || # "server accepts handled requests request_time" or only "server accepts handled requests"
          egrep( string:res, pattern:"^Reading: [0-9]+ Writing: [0-9]+ Waiting: [0-9]+" ) ) ) { # Reading: 0 Writing: 1 Waiting: 0
      extra = '- Output of the HttpStubStatusModule module available at ' + http_report_vuln_url( port:port, url:ngnx_status, url_only:TRUE );
      break;
    }
  }

  set_kb_item( name:"nginx/detected", value:TRUE );
  set_kb_item( name:"nginx/http/detected", value:TRUE );
  set_kb_item( name:"nginx/http/port", value:port );
  set_kb_item( name:"nginx/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + vers + "#---#" + concl + "#---#" + conclUrl + "#---#" + extra );
}

exit( 0 );