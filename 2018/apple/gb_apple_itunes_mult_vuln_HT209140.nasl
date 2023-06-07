# Copyright (C) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814308");
  script_version("2022-02-09T12:06:17+0000");
  script_cve_id("CVE-2018-4191", "CVE-2018-4311", "CVE-2018-4316", "CVE-2018-4299",
                "CVE-2018-4323", "CVE-2018-4328", "CVE-2018-4358", "CVE-2018-4359",
                "CVE-2018-4319", "CVE-2018-4309", "CVE-2018-4197", "CVE-2018-4306",
                "CVE-2018-4312", "CVE-2018-4314", "CVE-2018-4315", "CVE-2018-4317",
                "CVE-2018-4318", "CVE-2018-4345", "CVE-2018-4361");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-09 12:06:17 +0000 (Wed, 09 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-04 20:03:00 +0000 (Thu, 04 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-10-04 10:51:28 +0530 (Thu, 04 Oct 2018)");
  script_name("Apple iTunes Multiple Vulnerabilities (HT209140)");

  script_tag(name:"summary", value:"Apple iTunes is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues

  - A cross-origin issue with iframe elements

  - A cross-site scripting issue in Safari

  - A use after free issue

  - A memory consumption issue");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct
  cross-site scripting (XSS) and arbitrary code execution attacks.");

  script_tag(name:"affected", value:"Apple iTunes versions before 12.9.");

  script_tag(name:"solution", value:"Update to version 12.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT209140");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"12.9")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"12.9", install_path: path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
