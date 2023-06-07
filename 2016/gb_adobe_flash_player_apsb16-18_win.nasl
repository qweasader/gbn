# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808168");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2016-4122", "CVE-2016-4123", "CVE-2016-4124", "CVE-2016-4125",
                "CVE-2016-4127", "CVE-2016-4128", "CVE-2016-4129", "CVE-2016-4130",
                "CVE-2016-4131", "CVE-2016-4132", "CVE-2016-4133", "CVE-2016-4134",
                "CVE-2016-4135", "CVE-2016-4136", "CVE-2016-4137", "CVE-2016-4138",
                "CVE-2016-4139", "CVE-2016-4140", "CVE-2016-4141", "CVE-2016-4142",
                "CVE-2016-4143", "CVE-2016-4144", "CVE-2016-4145", "CVE-2016-4146",
                "CVE-2016-4147", "CVE-2016-4148", "CVE-2016-4149", "CVE-2016-4150",
                "CVE-2016-4151", "CVE-2016-4152", "CVE-2016-4153", "CVE-2016-4154",
                "CVE-2016-4155", "CVE-2016-4156", "CVE-2016-4166", "CVE-2016-4171");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-24 16:33:00 +0000 (Wed, 24 Nov 2021)");
  script_tag(name:"creation_date", value:"2016-06-17 10:49:19 +0530 (Fri, 17 Jun 2016)");
  script_name("Adobe Flash Player Security Update (apsb16-18) - Windows");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A type confusion vulnerabilities.

  - The use-after-free vulnerabilities.

  - The heap buffer overflow vulnerabilities.

  - The memory corruption vulnerabilities.

  - A vulnerability in the directory search path used to find resources.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the same-origin-policy and lead to information disclosure,
  and code execution.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  18.0.0.360 and 21.x before 22.0.0.192.");

  script_tag(name:"solution", value:"Update to version 18.0.0.360, 22.0.0.192 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb16-18.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"21", test_version2:"22.0.0.191")) {
  fix = "22.0.0.192";
  VULN = TRUE;
}

else if(version_is_less(version:vers, test_version:"18.0.0.360")) {
  fix = "18.0.0.360";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);