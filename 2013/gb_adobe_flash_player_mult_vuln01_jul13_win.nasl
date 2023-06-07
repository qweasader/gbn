###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities-01 July13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803831");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3347", "CVE-2013-3345", "CVE-2013-3344");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-07-25 17:21:07 +0530 (Thu, 25 Jul 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (APSB13-17) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 11.7.700.232, 11.8.800.94 or later.");

  script_tag(name:"insight", value:"Multiple unspecified errors and an integer overflow error exists
  when resampling a PCM buffer.");

  script_tag(name:"affected", value:"Adobe Flash Player before 11.7.700.232 and 11.8.x before 11.8.800.94.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary code on the target system will cause heap-based buffer overflow or cause memory
  corruption via unspecified vectors.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/53975");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61043");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61045");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61048");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-17.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"11.7.700.232" ) ||
    version_in_range( version:vers, test_version:"11.8.0", test_version2:"11.8.800.93" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"11.7.700.232 or 11.8.800.94", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
