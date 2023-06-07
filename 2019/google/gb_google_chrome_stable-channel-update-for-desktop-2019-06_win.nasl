# Copyright (C) 2019 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA


CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815202");
  script_version("2022-08-01T10:11:45+0000");
  script_cve_id("CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831",
                "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835",
                "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839",
                "CVE-2019-5840");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-08-01 10:11:45 +0000 (Mon, 01 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-29 17:23:00 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2019-06-06 10:38:43 +0530 (Thu, 06 Jun 2019)");
  script_name("Google Chrome Security Updates (stable-channel-update-for-desktop-2019-06)-Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A use after free error in ServiceWorker.

  - A use after free error in Download Manager.

  - An incorrectly credentialed requests issue in CORS.

  - An incorrect map processing issue in V8.

  - An incorrect CORS handling issue in XHR.

  - An inconsistent security UI placement issue.

  - A URL spoof error in Omnibox.

  - An out of bounds read error in Swiftshader.

  - A heap buffer overflow error in Angle.

  - A cross-origin resources size disclosure in Appcache.

  - An overly permissive tab access in Extensions.

  - An incorrect handling of certain code points in Blink.

  - A popup blocker bypass issue.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the browser, obtain sensitive
  information, conduct spoofing attacks, bypass security restrictions, and
  perform unauthorized actions, or cause denial-of-service conditions.");

  script_tag(name:"affected", value:"Google Chrome version prior to 75.0.3770.80 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  75.0.3770.80 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2019/06/stable-channel-update-for-desktop.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"75.0.3770.80"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"75.0.3770.80", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
