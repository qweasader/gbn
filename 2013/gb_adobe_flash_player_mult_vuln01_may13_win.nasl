###############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Multiple Vulnerabilities -01 May 13 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.803494");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2013-3335", "CVE-2013-3334", "CVE-2013-3333", "CVE-2013-3332",
                "CVE-2013-3331", "CVE-2013-3330", "CVE-2013-3329", "CVE-2013-3328",
                "CVE-2013-3327", "CVE-2013-3326", "CVE-2013-3325", "CVE-2013-3324",
                "CVE-2013-2728");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-05-21 13:26:52 +0530 (Tue, 21 May 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities -01 May 13 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59891");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59892");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59893");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59894");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59895");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59896");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59897");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59898");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59899");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59901");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb13-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.76 and 11.x before 11.7.700.170
  on Windows");
  script_tag(name:"insight", value:"Multiple memory corruption flaws due to improper sanitation of user
  supplied input via a file.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.86 or 11.7.700.202 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"10.3.183.75" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.7.700.169" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.86 or 11.7.700.202", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );