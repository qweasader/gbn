###############################################################################
# OpenVAS Vulnerability Test
#
# Tomcat 4.x JSP Source Exposure
#
# Authors:
# Felix Huber <huberfelix@webtopia.de>
# Changes by Tenable : removed un-necessary requests
#
# Copyright:
# Copyright (C) 2002 Felix Huber
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11176");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-1148");
  script_name("Tomcat 4.x JSP Source Exposure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Felix Huber");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_consolidation.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_xref(name:"URL", value:"http://jakarta.apache.org/builds/jakarta-tomcat-4.0/release/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/5786");

  script_tag(name:"solution", value:"Upgrade to the last releases 4.0.5 and 4.1.12.
  See the linked reference for the last releases.");

  script_tag(name:"summary", value:"Tomcat 4.0.4 and 4.1.10 (probably all other
  earlier versions also) are vulnerable to source code exposure by using the default
  servlet org.apache.catalina.servlets.DefaultServlet.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );
host = http_host_name( dont_add_port:TRUE );

files = http_get_kb_file_extensions( port:port, host:host, ext:"jsp" );

if( ! isnull( files ) ) {
  files = make_list( files );
  file = files[0];
} else {
  file = "/index.jsp";
}

url = "/servlet/org.apache.catalina.servlets.DefaultServlet" + file;
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( isnull( res) ) exit( 0 );

if( "<%@" >< res ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

if( res =~ "^HTTP/1\.[01] 200" ) {
  if( "Server: Apache Tomcat/4\." >< res ) {
    report = http_report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
