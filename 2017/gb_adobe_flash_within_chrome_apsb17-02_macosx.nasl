##############################################################################
# OpenVAS Vulnerability Test
#
# Adobe Flash Player Within Google Chrome Security Update (apsb17-02) - Mac OS X
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
  script_oid("1.3.6.1.4.1.25623.1.0.810620");
  script_version("2023-01-30T10:09:19+0000");
  script_cve_id("CVE-2017-2925", "CVE-2017-2926", "CVE-2017-2927", "CVE-2017-2928",
                "CVE-2017-2930", "CVE-2017-2931", "CVE-2017-2932", "CVE-2017-2933",
                "CVE-2017-2934", "CVE-2017-2935", "CVE-2017-2936", "CVE-2017-2937",
                "CVE-2017-2938");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-30 10:09:19 +0000 (Mon, 30 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-27 17:56:00 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-03-14 17:38:23 +0530 (Tue, 14 Mar 2017)");
  script_name("Adobe Flash Player Within Google Chrome Security Update (apsb17-02) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A security bypass vulnerability.

  - Multiple use-after-free vulnerabilities.

  - The heap buffer overflow vulnerabilities.

  - The memory corruption vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to take control of the affected system, lead to code
  execution and information disclosure.");

  script_tag(name:"affected", value:"Adobe Flash Player for chrome versions
  before 24.0.0.194 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player for chrome
  version 24.0.0.194 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb17-02.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95341");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95342");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95347");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95350");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_flash_player_within_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Chrome/MacOSX/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"24.0.0.194"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"24.0.0.194");
  security_message(data:report);
  exit(0);
}