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
  script_oid("1.3.6.1.4.1.25623.1.0.900835");
  script_version("2022-05-09T13:48:18+0000");
  script_tag(name:"last_modification", value:"2022-05-09 13:48:18 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7002");
  script_name("PHP Security Bypass Vulnerability - Aug09");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl");
  script_mandatory_keys("php/detected");

  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/383831.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31064");
  script_xref(name:"URL", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/31064.php");

  script_tag(name:"impact", value:"Successful exploitation will let the local attacker execute arbitrary code and
  can bypass security restriction in the context of the web application.");

  script_tag(name:"affected", value:"PHP version 5.2.5.");

  script_tag(name:"insight", value:"Error exists when application fails to enforce 'safe_mode_exec_dir' and
  'open_basedir' restrictions for certain functions, which can be caused via
  the exec, system, shell_exec, passthru, or popen functions, possibly
  involving pathnames such as 'C:' drive notation.");

  script_tag(name:"solution", value:"Update to PHP version 5.3.2 or later.");

  script_tag(name:"summary", value:"PHP is prone to a security bypass vulnerability.");

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

if( version_is_equal( version:vers, test_version:"5.2.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.3.2" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
