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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:brackets";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815699");
  script_version("2021-10-11T11:05:30+0000");
  script_cve_id("CVE-2019-8255");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-11 11:05:30 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-12-12 10:56:11 +0530 (Thu, 12 Dec 2019)");
  script_name("Adobe Brackets Command Injection Vulnerability (APSB19-57)-Windows");

  script_tag(name:"summary", value:"Adobe Brackets is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to command injection error
  in the application.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers to
  run arbitrary code on affected system.");

  script_tag(name:"affected", value:"Adobe Brackets version 1.14 and earlier");

  script_tag(name:"solution", value:"Update Adobe Brackets to version 1.14.1 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/coldfusion/apsb19-57.html");
  script_xref(name:"URL", value:"http://brackets.io");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_brackets_detect_win.nasl");
  script_mandatory_keys("AdobeBrackets/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if(version && version_is_less(version: version, test_version: "1.14.1"))
{
  report = report_fixed_ver(installed_version: version, fixed_version: "1.14.1", install_path: path);
  security_message(data: report);
  exit(0);
}
exit(99);
