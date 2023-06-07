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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:adobe:indesign_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814965");
  script_version("2022-10-13T10:20:57+0000");
  script_cve_id("CVE-2019-7107");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-10-13 10:20:57 +0000 (Thu, 13 Oct 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-12 16:21:00 +0000 (Wed, 12 Oct 2022)");
  script_tag(name:"creation_date", value:"2019-04-11 14:52:03 +0530 (Thu, 11 Apr 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe InDesign Arbitrary Code Execution Vulnerability-APSB19-23 (Windows)");

  script_tag(name:"summary", value:"Adobe InDesign is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists de to unsafe hyperlink processing.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application. Failed
  attacks may cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Adobe InDesign versions 14.0.1 and earlier on Windows.");

  script_tag(name:"solution", value:"Upgrade to version 14.0.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/indesign/apsb19-23.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/107821");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_mandatory_keys("Adobe/InDesign/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );

vers = infos['version'];
path = infos['location'];
if(version_is_less(version:vers, test_version:"14.0.2"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"14.0.2", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);
