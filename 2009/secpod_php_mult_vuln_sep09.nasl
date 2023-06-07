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
  script_oid("1.3.6.1.4.1.25623.1.0.900871");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3291", "CVE-2009-3292", "CVE-2009-3293", "CVE-2009-5016");
  script_name("PHP Multiple Vulnerabilities - Sep09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/36791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36449");
  script_xref(name:"URL", value:"http://www.php.net/releases/5_2_11.php");
  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php#5.2.11");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/09/20/1");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to spoof certificates and can
  cause unknown impacts in the context of the web application.");

  script_tag(name:"affected", value:"PHP version prior to 5.2.11");

  script_tag(name:"insight", value:"- An error in 'php_openssl_apply_verification_policy' function that does not
  properly perform certificate validation.

  - An input validation error exists in the processing of 'exif' data.

  - An unspecified error exists related to the sanity check for the color index
  in the 'imagecolortransparent' function.");

  script_tag(name:"solution", value:"Update to version 5.2.11 or later.");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) )
  exit( 0 );

if( version_is_less( version:phpVer, test_version:"5.2.11" ) ) {
  report = report_fixed_ver( installed_version:phpVer, fixed_version:"5.2.11" );
  security_message( data:report, port:phpPort );
  exit( 0 );
}

exit( 99 );
