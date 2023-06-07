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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816579");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-3759", "CVE-2020-3760");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 15:47:00 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-13 11:19:10 +0530 (Thu, 13 Feb 2020)");
  script_name("Adobe Digital Editions Multiple Vulnerabilities (APSB20-07) - Windows");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to code multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to various buffer
  errors and command injection flaws.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive data and execute arbitrary code");

  script_tag(name:"affected", value:"Adobe Digital Edition versions prior to 4.5.11
 .");

  script_tag(name:"solution", value:"Update to Adobe Digital Edition version
  4.5.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb20-07.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"4.5.11")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.5.11", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);