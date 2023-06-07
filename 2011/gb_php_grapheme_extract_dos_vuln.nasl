# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801860");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-0420");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("PHP 'grapheme_extract()' NULL Pointer Dereference Denial Of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16182");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46429");
  script_xref(name:"URL", value:"http://securityreason.com/achievement_securityalert/94");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc/php/php-src/trunk/ext/intl/grapheme/grapheme_string.c?r1=306449&r2=306448&pathrev=306449");
  script_xref(name:"URL", value:"http://svn.php.net/viewvc?view=revision&revision=306449");

  script_tag(name:"impact", value:"Successful exploitation could allows context-dependent attackers to cause a
  denial of service.");

  script_tag(name:"affected", value:"PHP version 5.3.5.");

  script_tag(name:"insight", value:"A flaw is caused by a NULL pointer dereference in the 'grapheme_extract()'
  function in the Internationalization extension (Intl) for ICU which allows
  context-dependent attackers to cause a denial of service via an invalid size
  argument.");

  script_tag(name:"solution", value:"Apply the patch the referenced advisory.");

  script_tag(name:"summary", value:"PHP is prone to a NULL pointer dereference denial of service vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_equal(version:phpVer, test_version:"5.3.5")){
  report = report_fixed_ver(installed_version:phpVer, fixed_version:"5.3.6");
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
