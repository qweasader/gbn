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
  script_oid("1.3.6.1.4.1.25623.1.0.826822");
  script_version("2023-03-15T10:19:45+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-30521", "CVE-2021-30522", "CVE-2021-30523", "CVE-2021-30524",
                "CVE-2021-30525", "CVE-2021-30526", "CVE-2021-30527", "CVE-2021-30528",
                "CVE-2021-30529", "CVE-2021-30530", "CVE-2021-30531", "CVE-2021-30532",
                "CVE-2021-30533", "CVE-2021-30534", "CVE-2021-30535", "CVE-2021-30542",
                "CVE-2021-30543", "CVE-2021-30558", "CVE-2021-30536", "CVE-2021-30537",
                "CVE-2021-30538", "CVE-2021-30539", "CVE-2021-30540");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-15 10:19:45 +0000 (Wed, 15 Mar 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-18 03:15:00 +0000 (Sun, 18 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-12-28 13:21:37 +0530 (Wed, 28 Dec 2022)");
  script_name("Google Chrome Security Update(stable-channel-update-for-desktop_25-2021-05)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Heap buffer overflow in Autofill.

  - Use after free errors in WebAudio, WebRTC, TabStrip, TabGroups, WebUI, WebAuthentication, Bookmarks.

  - Out of bounds write in TabStrip.

  - Out of bounds memory access in WebAudio.

  - Insufficient policy enforcement in Content Security Policy.

  - Insufficient policy enforcement in PopupBlocker.

  - Insufficient policy enforcement in iFrameSandbox.

  - Double free in ICU.

  - Insufficient policy enforcement in content security policy.

  - Out of bounds read in V8.

  - Insufficient policy enforcement in cookies.

  - Incorrect security UI in payments.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions,
  conduct spoofing and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to
  91.0.4472.77 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  91.0.4472.77 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/05/stable-channel-update-for-desktop_25.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"91.0.4472.77"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.0.4472.77", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
