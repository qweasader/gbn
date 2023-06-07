##############################################################################
# OpenVAS Vulnerability Test
#
# Kerio Control Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:kerio:control";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140068");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2016-11-17 12:58:24 +0100 (Thu, 17 Nov 2016)");
  script_tag(name:"qod", value:"80");
  script_name("Kerio Control Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Kerio Control is affected by multiple vulnerabilities.");

  script_tag(name:"insight", value:"1) Unsafe usage of the PHP unserialize function and outdated PHP version leads  to remote-code-execution

  2) PHP script allows heap spraying

  3) CSRF Protection Bypass

  4) Reflected Cross Site Scripting (XSS)

  5) Missing memory corruption protections

  6) Information Disclosure leads to ASLR bypass

  7) Remote Code Execution as administrator

  8) Login not protected against brute-force attacks

  See the referenced advisory for further information.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request (XSS) and check the response.");

  script_tag(name:"affected", value:"Kerio Control < 9.1.3");

  script_tag(name:"solution", value:"Update to Kerio Control 9.1.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20160922-0_Kerio_Control_Potential_backdoor_access_through_multiple_vulnerabilities_v10.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_kerio_control_web_interface_detect.nasl");
  script_mandatory_keys("kerio/control/webiface");
  script_require_ports("Services/www", 4081);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

url = '/admin/internal/dologin.php?hash=%0D%0A%22%3E%3Cscript%3Ealert(/vt-xss-test/);%3C/script%3E%3C!--';
if( http_vuln_check( port:port, url:url, pattern:'"><script>alert\\(/vt-xss-test/\\);</script><!--</a>', extra_check:make_list( "302 Found" ), check_nomatch:make_list( "Location:" ) ) ) {
  report = http_report_vuln_url( port:port, url:url);
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
