# Copyright (C) 2022 Greenbone Networks GmbH
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


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.820007");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-0603", "CVE-2022-0604", "CVE-2022-0605", "CVE-2022-0606",
                "CVE-2022-0607", "CVE-2022-0608", "CVE-2022-0609", "CVE-2022-0610");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 17:17:00 +0000 (Fri, 08 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-02-16 14:35:39 +0530 (Wed, 16 Feb 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_14-2022-02)-MAC OS X");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Multiple use after free errors in File Manager, Webstore API, ANGLE, GPU,
    Animation.

  - Heap buffer overflow error in Tab Groups.

  - Integer overflow error in Mojo.

  - Inappropriate implementation in Gamepad API.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to
  execute arbitrary code, cause denial of service and leak sensitive information.");

  script_tag(name:"affected", value:"Google Chrome version prior to 98.0.4758.102
  on MAC OS X");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 98.0.4758.102
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2022/02/stable-channel-update-for-desktop_14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"98.0.4758.102"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"98.0.4758.102", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
