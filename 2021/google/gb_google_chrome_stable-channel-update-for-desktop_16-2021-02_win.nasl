# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.817937");
  script_version("2021-10-05T08:17:22+0000");
  script_cve_id("CVE-2021-21149", "CVE-2021-21150", "CVE-2021-21151", "CVE-2021-21152",
                "CVE-2021-21153", "CVE-2021-21154", "CVE-2021-21155", "CVE-2021-21156",
                "CVE-2021-21157");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 08:17:22 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");
  script_tag(name:"creation_date", value:"2021-02-23 10:52:28 +0530 (Tue, 23 Feb 2021)");
  script_name("Google Chrome Security Update (stable-channel-update-for-desktop_16-2021-02) - Windows");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Stack overflow error in Data Transfer.

  - Use after free error in Downloads.

  - Use after free error in Payments.

  - Heap buffer overflow error in Media.

  - Stack overflow error in GPU Process.

  - Heap buffer overflow error in Tab Strip .

  - Heap buffer overflow error in V8.

  - Use after free error in Web Sockets.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to execute arbitrary code, disclose sensitive information and
  take control of an affected system.");

  script_tag(name:"affected", value:"Google Chrome version prior to 88.0.4324.182
  on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 88.0.4324.182
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2021/02/stable-channel-update-for-desktop_16.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"88.0.4324.182"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"88.0.4324.182", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
