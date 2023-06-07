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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800373");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-03-17 05:28:51 +0100 (Tue, 17 Mar 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-0754");
  script_name("PHP 'mbstring.func_overload' DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://bugs.php.net/bug.php?id=27421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33542");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479272");

  script_tag(name:"impact", value:"Successful exploitation will let the local attackers to crash an affected web server.");

  script_tag(name:"affected", value:"PHP version 4.4.4 and prior

  PHP 5.1.x to 5.1.6

  PHP 5.2.x to 5.2.5");

  script_tag(name:"insight", value:"This bug is due to an error in 'mbstring.func_overload' setting in .htaccess
  file. It can be exploited via modifying behavior of other sites hosted on
  the same web server which causes this setting to be applied to other virtual
  hosts on the same server.");

  script_tag(name:"solution", value:"Update to version 4.4.5, 5.1.7, 5.2.6 or later.");

  script_tag(name:"summary", value:"PHP is prone to a denial of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less_equal( version:vers, test_version:"4.4.4" ) ||
    version_in_range( version:vers, test_version:"5.1", test_version2:"5.1.6" ) ||
    version_in_range( version:vers, test_version:"5.2", test_version2:"5.2.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"4.4.5/5.1.7/5.2.6" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
