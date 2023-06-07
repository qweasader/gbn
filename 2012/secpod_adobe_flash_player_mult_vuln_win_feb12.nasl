# Copyright (C) 2012 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802803");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-0751", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754",
                "CVE-2012-0757", "CVE-2012-0756", "CVE-2012-0767");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2012-02-22 11:17:41 +0530 (Wed, 22 Feb 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Windows) - Feb12");
  script_xref(name:"URL", value:"http://secunia.com/advisories/48033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51999");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52040");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026694");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/48033");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-03.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application or cause a denial of service condition.");

  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.15
  Adobe Flash Player version 11.x through 11.1.102.55 and prior on Windows.");

  script_tag(name:"insight", value:"Flaws are due to

  - A memory corruption error in ActiveX control.

  - A type confusion memory corruption error.

  - An unspecified error related to MP4 parsing.

  - Many unspecified errors which allows to bypass certain security
  restrictions.

  - Improper validation of user supplied input which allows attackers
  to execute arbitrary HTML and script code in a user's browser session.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 11.1.102.62 or later.");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"10.3.183.15" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.1.102.55" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"11.1.102.62", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
