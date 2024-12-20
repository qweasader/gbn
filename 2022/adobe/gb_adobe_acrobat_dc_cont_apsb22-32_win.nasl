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

CPE = "cpe:/a:adobe:acrobat_dc_continuous";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821182");
  script_version("2023-10-18T05:05:17+0000");
  script_cve_id("CVE-2022-34230", "CVE-2022-34229", "CVE-2022-34228", "CVE-2022-34227",
                "CVE-2022-34226", "CVE-2022-34225", "CVE-2022-34224", "CVE-2022-34223",
                "CVE-2022-34222", "CVE-2022-34237", "CVE-2022-34238", "CVE-2022-34239",
                "CVE-2022-34236", "CVE-2022-34221", "CVE-2022-34234", "CVE-2022-34220",
                "CVE-2022-34219", "CVE-2022-34217", "CVE-2022-34216", "CVE-2022-34233",
                "CVE-2022-34215", "CVE-2022-34232", "CVE-2022-35669");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-18 05:05:17 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-21 17:57:00 +0000 (Thu, 21 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-13 09:06:05 +0530 (Wed, 13 Jul 2022)");
  script_name("Adobe Acrobat DC Continuous Security Update (APSB22-32) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat Reader is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - Access of Uninitialized Pointer.

  - out-of-bounds read errors.

  - Access of Resource Using Incompatible Type.

  - out-of-bounds write errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and leak memory on the target system.");

  script_tag(name:"affected", value:"Adobe Acrobat DC (Continuous) versions
  22.001.20142 and earlier on Windows.");

  script_tag(name:"solution", value:"Update Adobe Acrobat DC (Continuous)
  to version 22.001.20169 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb22-32.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_cont_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Continuous/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"22.001.20142"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"22.001.20169", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
