###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Sametime Server 'stcenter.nsf' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801901");
  script_version("2022-02-17T14:14:34+0000");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2011-1106");

  script_name("IBM Lotus Sametime Multiple Cross-Site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43430/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65555");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/46481.txt");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=899&uid=swg21496276");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"IBM Lotus Sametime version 8.0 and 8.0.1");

  script_tag(name:"insight", value:"Input passed to the 'authReasonCode' parameter in 'stcenter.nsf'
  when 'OpenDatabase' is set, is not properly sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue, please refer
  below link for patch information.");

  script_tag(name:"summary", value:"IBM Lotus Sametime Server is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/stcenter.nsf?OpenDatabase&authReasonCode='><script>alert('XSS-TEST');</script>'";

if( http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"<script>alert\('XSS-TEST'\)</script>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
