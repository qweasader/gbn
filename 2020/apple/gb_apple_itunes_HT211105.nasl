# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816720");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-3910", "CVE-2020-3909", "CVE-2020-3911", "CVE-2020-3901",
                "CVE-2020-3887", "CVE-2020-3895", "CVE-2020-3900", "CVE-2020-3894",
                "CVE-2020-3897", "CVE-2020-9783", "CVE-2020-3899", "CVE-2020-3902",
                "CVE-2020-3885");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-16 17:15:00 +0000 (Fri, 16 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-03-26 16:23:05 +0530 (Thu, 26 Mar 2020)");
  script_name("Apple iTunes Security Update (HT211105)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple buffer overflow issues due to improper size validation and bounds checking.

  - A type confusion issue due to improper memory handling.

  - A logic issue due to improper restrictions.

  - A memory corruption issue due to improper memory handling.

  - A race condition issue due to improper validation.

  - A use after free issue due to improper memory management.

  - A memory consumption issue due to improper memory handling.

  - An input validation issue due to improper validation.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code, read restricted memory and conduct cross site scripting
  attacks.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.10.5");

  script_tag(name:"solution", value:"Update to Apple iTunes 12.10.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT211105");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"12.10.5")) {
  report = report_fixed_ver(installed_version: vers, fixed_version:"12.10.5", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);