##############################################################################
# OpenVAS Vulnerability Test
#
# Piwigo Cross Site Request Forgery and Path Traversal Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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

CPE = "cpe:/a:piwigo:piwigo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803340");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-1468", "CVE-2013-1469");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-03-21 13:40:26 +0530 (Thu, 21 Mar 2013)");
  script_name("Piwigo Cross Site Request Forgery and Path Traversal Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("piwigo/installed");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Feb/152");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58016");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/58080");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24561");
  script_xref(name:"URL", value:"http://www.htbridge.com/advisory/HTB23144");
  script_xref(name:"URL", value:"http://piwigo.org/releases/2.4.7");

  script_tag(name:"insight", value:"- Flaw in the LocalFiles Editor plugin, it does not require multiple steps
    or explicit confirmation for sensitive transactions.

  - Input passed via 'dl' parameter to install.php is not properly sanitized before being used.");

  script_tag(name:"solution", value:"Upgrade to Piwigo version 2.4.7");

  script_tag(name:"summary", value:"Piwigo is prone to cross site request forgery and path traversal vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to create arbitrary PHP
  file or to retrieve and delete arbitrary files in the context of the
  affected application.");

  script_tag(name:"affected", value:"Piwigo version 2.4.6 and prior");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + '/install.php?dl=/../../local/config/ovtestlmn678.php';

# Actual file, '/database.inc.php' gets deleted and information cannot be fetched.
# Hence we are using dummy file 'ovtestlmn678.php' to check the
# response. The patched version of application will generate a different
# response.

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:"Piwigo is already installed" ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
