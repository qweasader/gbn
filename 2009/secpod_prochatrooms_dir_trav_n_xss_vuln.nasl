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

CPE = "cpe:/a:pro_chat_rooms:pro_chat_rooms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900331");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-31 07:06:59 +0200 (Tue, 31 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2008-6501", "CVE-2008-6502");
  script_name("Directory Traversal And XSS Vulnerability In Pro Chat Rooms");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_prochatrooms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ProChatRooms/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33088");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32758");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/6612");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7409");

  script_tag(name:"impact", value:"Successful exploitation could result in Directory Traversal, Cross-Site
  Scripting or Cross-Site Request Forgery attack by execute arbitrary HTML and script code on the affected application.");

  script_tag(name:"affected", value:"Pro Chat Rooms version 3.0.3 and prior on all running platform.");

  script_tag(name:"insight", value:"- Error in profiles/index.php and profiles/admin.php file allows remote
  attackers to inject arbitrary web script or HTML via the 'gud' parameter.

  - Error in sendData.php file allows remote authenticated users to select
  an arbitrary local PHP script as an avatar via a ..(dot dot) in the 'avatar' parameter.");

  script_tag(name:"solution", value:"Upgrade to Pro Chat Rooms version 6.0 or later.");

  script_tag(name:"summary", value:"Pro Chat Rooms is prone to Directory Traversal and XSS vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  script_xref(name:"URL", value:"http://www.prochatrooms.com");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/profiles/index.php?gud=<script>alert(document.cookie)</script>";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document.cookie\)</script>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
