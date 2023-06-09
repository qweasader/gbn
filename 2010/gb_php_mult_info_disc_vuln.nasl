# Copyright (C) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801359");
  script_version("2021-04-13T14:13:08+0000");
  script_tag(name:"last_modification", value:"2021-04-13 14:13:08 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-2190", "CVE-2010-2191");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("PHP Multiple Information Disclosure Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://www.php-security.org/2010/05/30/mops-2010-048-php-substr_replace-interruption-information-leak-vulnerability/index.html");
  script_xref(name:"URL", value:"http://www.php-security.org/2010/05/30/mops-2010-047-php-trimltrimrtrim-interruption-information-leak-vulnerability/index.html");

  script_tag(name:"impact", value:"Successful exploitation could allow local attackers to bypass
  certain security restrictions and to obtain sensitive information.");

  script_tag(name:"affected", value:"PHP version 5.2 through 5.2.13 and 5.3 through 5.3.2");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error in 'trim()', 'ltrim()', 'rtrim()' and 'substr_replace()' functions,
  which causes a userspace interruption of an internal function within the
  call time pass by reference feature.

  - Error in 'parse_str()', 'preg_match()', 'unpack()' and 'pack()' functions,
  'ZEND_FETCH_RW()', 'ZEND_CONCAT()', and 'ZEND_ASSIGN_CONCAT()' opcodes, and
  the 'ArrayObject::uasort' method, trigger memory corruption by causing a
  userspace interruption of an internal function or handler.");

  script_tag(name:"solution", value:"Update to PHP version 5.2.14/5.3.3 or later");

  script_tag(name:"summary", value:"PHP is prone to multiple information disclosure vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.2", test_version2:"5.2.13" ) ||
    version_in_range( version:vers, test_version:"5.3", test_version2:"5.3.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.14/5.3.3" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
