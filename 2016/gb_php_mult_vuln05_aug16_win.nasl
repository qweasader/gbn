# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.808674");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2015-4644", "CVE-2015-4643", "CVE-2015-4598", "CVE-2015-4642");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-22 01:29:00 +0000 (Fri, 22 Sep 2017)");
  script_tag(name:"creation_date", value:"2016-08-31 16:41:23 +0530 (Wed, 31 Aug 2016)");
  script_name("PHP Multiple Vulnerabilities - 05 - Aug16 (Windows)");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Improper validation of token extraction for table names, in the
    php_pgsql_meta_data function in pgsql.c in the PostgreSQL extension.

  - Integer overflow in the ftp_genlist function in ext/ftp/ftp.c

  - PHP does not ensure that pathnames lack %00 sequences.

  - An error in 'escapeshellarg' function in 'ext/standard/exec.c'
    script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to cause a denial of service, to read or write to arbitrary
  files, also execute arbitrary code via a long reply to a LIST command, leading
  to a heap-based buffer overflow.");

  script_tag(name:"affected", value:"PHP versions prior to 5.4.42, 5.5.x before
  5.5.26, and 5.6.x before 5.6.10 on Windows");

  script_tag(name:"solution", value:"Update to PHP version 5.4.42,
  or 5.5.26, or 5.6.10, or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.php.net/ChangeLog-5.php");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75291");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75292");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75244");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75290");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("secpod_php_smb_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_windows");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( phpPort = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! phpVer = get_app_version( cpe:CPE, port:phpPort ) ) exit( 0 );

if(version_is_less(version:phpVer, test_version:"5.4.42"))
{
  fix = '5.4.42';
  VULN = TRUE;
}

else if(phpVer =~ "^5\.5")
{
  if(version_in_range(version:phpVer, test_version:"5.5.0", test_version2:"5.5.25"))
  {
    fix = '5.5.26';
    VULN = TRUE;
  }
}

else if(phpVer =~ "^5\.6")
{
  if(version_in_range(version:phpVer, test_version:"5.6.0", test_version2:"5.6.9"))
  {
    fix = '5.5.10';
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:phpVer, fixed_version:fix);
  security_message(data:report, port:phpPort);
  exit(0);
}

exit(99);
