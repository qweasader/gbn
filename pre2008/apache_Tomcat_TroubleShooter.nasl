###############################################################################
# OpenVAS Vulnerability Test
#
# Apache Tomcat TroubleShooter Servlet Installed
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
  script_oid("1.3.6.1.4.1.25623.1.0.11046");
  script_version("2022-05-12T09:32:01+0000");
  script_tag(name:"last_modification", value:"2022-05-12 09:32:01 +0000 (Thu, 12 May 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2002-2006");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4575");
  script_name("Apache Tomcat TroubleShooter Servlet Installed");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2002 Matt Moore");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_consolidation.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/tomcat/http/detected");

  script_tag(name:"solution", value:"Example files should not be left on production servers.");

  script_tag(name:"summary", value:"The remote Apache Tomcat Server is vulnerable to cross script scripting and
  path disclosure issues.");

  script_tag(name:"insight", value:"The default installation of Tomcat includes various sample jsp pages and
  servlets.

  One of these, the 'TroubleShooter' servlet, discloses various information about
  the system on which Tomcat is installed. This servlet can also be used to
  perform cross-site scripting attacks against third party users.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = "/examples/servlet/TroubleShooter";

req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req );

confirmed = string( "TroubleShooter Servlet Output" );
confirmed_too = string( "hiddenValue" );

if( ( confirmed >< res ) && ( confirmed_too >< res ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
