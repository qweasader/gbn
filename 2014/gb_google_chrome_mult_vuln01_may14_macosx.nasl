###############################################################################
# OpenVAS Vulnerability Test
#
# Google Chrome Multiple Vulnerabilities - 01 May14 (Mac OS X)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804601");
  script_version("2022-04-14T11:24:11+0000");
  script_cve_id("CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:11 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"creation_date", value:"2014-05-21 15:13:49 +0530 (Wed, 21 May 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 01 May14 (Mac OS X)");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/05/stable-channel-update.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67376");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - A use-after-free error in WebSockets.

  - An integer overflow error in the 'CharacterData::deleteData' and
  'CharacterData::replaceData' functions in dom/CharacterData.cpp.

  - A use-after-free error in the 'FrameSelection::updateAppearance' function in
  editing/FrameSelection.cpp related to editing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a denial of
  service and potentially execute arbitrary code.");

  script_tag(name:"affected", value:"Google Chrome version prior to 34.0.1847.137 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome 34.0.1847.137 or later.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"34.0.1847.137")){
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"34.0.1847.137");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
