##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Within Google Chrome Security Update (apsb17-07) - Windows
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player_chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810671");
  script_version("2023-01-30T10:09:19+0000");
  script_cve_id("CVE-2017-2997", "CVE-2017-2998", "CVE-2017-2999", "CVE-2017-3000",
                "CVE-2017-3001", "CVE-2017-3002", "CVE-2017-3003");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-24 14:31:00 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-03-18 16:20:20 +0530 (Sat, 18 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (apsb17-07) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A buffer overflow vulnerability.

  - Multiple memory corruption vulnerabilities.

  - A random number generator vulnerability used for constant blinding.

  - Multiple use-after-free vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities
  will allow remote attackers to execute arbitrary code on the target user's
  system and that could potentially allow an attacker to take control of the
  affected system.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 25.0.0.127 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 25.0.0.127 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-07.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96861");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"25.0.0.127"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"25.0.0.127");
  security_message(data:report);
  exit(0);
}