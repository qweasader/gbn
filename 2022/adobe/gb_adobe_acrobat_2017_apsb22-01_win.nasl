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

CPE = "cpe:/a:adobe:acrobat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819932");
  script_version("2022-04-14T11:24:23+0000");
  script_cve_id("CVE-2021-44701", "CVE-2021-44702", "CVE-2021-44703", "CVE-2021-44704",
                "CVE-2021-44705", "CVE-2021-44706", "CVE-2021-44707", "CVE-2021-44708",
                "CVE-2021-44709", "CVE-2021-44710", "CVE-2021-44711", "CVE-2021-44712",
                "CVE-2021-44713", "CVE-2021-44714", "CVE-2021-44715", "CVE-2021-44739",
                "CVE-2021-44740", "CVE-2021-44741", "CVE-2021-44742", "CVE-2021-45060",
                "CVE-2021-45061", "CVE-2021-45062", "CVE-2021-45063", "CVE-2021-45064",
                "CVE-2021-45067", "CVE-2021-45068", "CVE-2022-24092", "CVE-2022-24091");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-14 11:24:23 +0000 (Thu, 14 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-21 20:34:00 +0000 (Fri, 21 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-13 11:07:26 +0530 (Thu, 13 Jan 2022)");
  script_name("Adobe Acrobat 2017 Security Update (APSB22-01) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Multiple out-of-bounds read errors.

  - Multiple out-of-bounds write errors.

  - Heap-based buffer overflow errors.

  - Access of uninitialized pointer.

  - An improper access control error.

  - Multiple input validation errors.

  - Multiple NULL pointer dereference errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, escalate privileges, cause denial of service, disclose
  sensitive information and bypass security restrictions on a vulnerable system.");

  script_tag(name:"affected", value:"Adobe Acrobat 2017 version prior to
  2017.011.30207 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Acrobat 2017 to version
  2017.011.30207 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-01.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"17.0", test_version2:"17.011.30204"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"17.011.30207(2017.011.30207)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
