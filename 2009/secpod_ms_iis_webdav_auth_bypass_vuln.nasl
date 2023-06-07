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

CPE = "cpe:/a:microsoft:internet_information_services";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900711");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1535");
  script_name("Microsoft IIS WebDAV Remote Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://view.samurajdata.se/psview.php?id=023287d6&page=2");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34993");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/advisory/971492");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/34993.rb");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/34993.txt");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft malicious UNICODE characters
  and send it over the context of IIS Webserver where WebDAV is enabled. As a
  result due to lack of security implementation check it will let the user fetch
  password protected directories without any valid authentications.");

  script_tag(name:"insight", value:"Due to the wrong implementation of UNICODE characters support (WebDAV extension)
  for Microsoft IIS Server which fails to decode the requested URL properly.
  Unicode character checks are being done after IIS Server internal security
  check, which lets the attacker execute any crafted UNICODE character in the
  HTTP requests to get information on any password protected directories without
  any authentication schema.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.

  Workaround: Disable WebDAV or upgrade to Microsoft IIS 7.0.");

  script_tag(name:"summary", value:"Microsoft IIS Webserver with WebDAV Module is prone to remote authentication bypass vulnerability.");

  script_tag(name:"affected", value:"Microsoft Internet Information Services version 5.0 to 6.0.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-020");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

host = http_host_name( port:port );

# For IIS WebDAV Enabled servers "MS-Author-VIA" header should be present.
# "OPTIONS" HTTP Method fetches which HTTP methods are supported for your server.
request = string( "OPTIONS / HTTP/1.0 \r\n\r\n",
                  "Host: ", host, "\r\n" );
response = http_keepalive_send_recv( port:port, data:request, bodyonly:FALSE );

if( "200 OK" >!< response && "Server: Microsoft-IIS" >!< response ) {

  request = string( "OPTIONS / HTTP/1.1 \r\n\r\n" );
  response = http_keepalive_send_recv( port:port, data:request, bodyonly:FALSE );

  if( "200 OK" >!< response && "Server: Microsoft-IIS" >!< response ) {
    exit( 0 );
  }
}

if( "MS-Author-Via: DAV" >!< response )
  exit( 0 );

if( version_in_range( version:vers, test_version:"5.0", test_version2:"6.0" ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
