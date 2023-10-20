# Copyright (C) 2023 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:framemaker";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826928");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2023-21584", "CVE-2023-21619", "CVE-2023-21620", "CVE-2023-21621",
                "CVE-2023-21622");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-17 22:15:00 +0000 (Fri, 17 Feb 2023)");
  script_tag(name:"creation_date", value:"2023-02-16 12:12:21 +0530 (Thu, 16 Feb 2023)");
  script_name("Adobe Framemaker Security Update (apsb23-06) - Windows");

  script_tag(name:"summary", value:"Adobe Framemaker is prone to multiple
  vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An use after free error.

  - An out-of-bounds read error.

  - Multiple out-of-bounds write errors.

  - An input validation error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and leak memory on the system.");

  script_tag(name:"affected", value:"Adobe Framemaker 2022 Release prior to
  2022 Update 1, 2020 Release Update 4 and earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade Adobe Framemaker to 2020 Update 5 or
  2022 to 2022 Update 1 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/framemaker/apsb23-06.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_framemaker_detect_win.nasl");
  script_mandatory_keys("AdobeFrameMaker/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range_exclusive(version: vers, test_version_lo: "17.0", test_version_up: "17.0.1.305"))
{
  fix = "2022 Update 1 or later.";
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
