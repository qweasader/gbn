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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819774");
  script_version("2022-02-25T03:03:32+0000");
  script_cve_id("CVE-2022-23186", "CVE-2022-23189", "CVE-2022-23190", "CVE-2022-23191",
                "CVE-2022-23192", "CVE-2022-23193", "CVE-2022-23194", "CVE-2022-23195",
                "CVE-2022-23196", "CVE-2022-23197", "CVE-2022-23198", "CVE-2022-23199",
                "CVE-2022-23188");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-25 03:03:32 +0000 (Fri, 25 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 03:08:00 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 14:18:16 +0530 (Thu, 10 Feb 2022)");
  script_name("Adobe Illustrator Multiple Vulnerabilities (APSB22-07) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple out-of-bounds read errors.

  - Multiple NULL Pointer Dereference errors.

  - Access of Memory Location After End of Buffer.

  - Buffer Overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, cause denial of service and disclose sensitive
  information.");

  script_tag(name:"affected", value:"Adobe Illustrator 2021 25.4.3 and earlier,
  2022 26.0.2 versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator 2021 version
  25.4.4 or 26.0.3 or later. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/illustrator/apsb22-07.html");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"25.4.4")){
  fix = "25.4.4";
} else if(version_in_range(version:vers, test_version:"26.0", test_version2:"26.0.2")){
    fix = "26.0.3";
}

if(fix)
{
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
