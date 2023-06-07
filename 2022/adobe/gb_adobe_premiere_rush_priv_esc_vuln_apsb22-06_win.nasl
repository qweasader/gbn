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

CPE = "cpe:/a:adobe:premiere_rush";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.819997");
  script_version("2022-02-28T03:03:56+0000");
  script_cve_id("CVE-2022-23204");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-28 03:03:56 +0000 (Mon, 28 Feb 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-24 15:56:00 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-10 10:57:48 +0530 (Thu, 10 Feb 2022)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Premiere Rush Privilege Escalation Vulnerability (APSB22-06) - Windows");

  script_tag(name:"summary", value:"Adobe Premiere Rush privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds read error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to escalate privileges on the affected system.");

  script_tag(name:"affected", value:"Adobe Premiere Rush versions 2.0 and prior.");

  script_tag(name:"solution", value:"Update Adobe Premiere Rush to version 2.3
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/premiere_rush/apsb22-06.html");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_premiere_rush_detect_win.nasl");
  script_mandatory_keys("adobe/premiererush/win/detected");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"2.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:'2.3', install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
