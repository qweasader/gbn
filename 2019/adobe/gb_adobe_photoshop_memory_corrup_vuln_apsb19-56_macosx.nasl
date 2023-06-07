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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815698");
  script_version("2021-10-07T07:48:17+0000");
  script_cve_id("CVE-2019-8253", "CVE-2019-8254");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-10-07 07:48:17 +0000 (Thu, 07 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-12-12 12:24:08 +0530 (Thu, 12 Dec 2019)");
  script_name("Adobe Photoshop CC Multiple Memory Corruption Vulnerabilities-APSB19-56 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Photoshop CC is prone to multiple memory corruption vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple memory
  corruption errors in application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the application.");

  script_tag(name:"affected", value:"Adobe Photoshop CC 2019 20.0.7 and earlier
  and Adobe Photoshop CC 2020 21.0.1 and earlier versions on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Photoshop CC 2019 20.0.8
  or Photoshop CC 2020 21.0.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-56.html");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Photoshop/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:photoshop_cc2019", "cpe:/a:adobe:photoshop_cc2020");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^21\.") {
  if(version_is_less_equal(version:vers, test_version:"21.0.1")) {
    fix = "21.0.2";
    installed_ver = "Adobe Photoshop CC 2020";
  }
}

else if(vers =~ "^20\.") {
  if(version_is_less_equal(version:vers, test_version:"20.0.7")) {
    fix = "20.0.8";
    installed_ver = "Adobe Photoshop CC 2019";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:installed_ver + " " + vers, fixed_version:fix, install_path:path);
  security_message(data:report);
  exit(0);
}

exit(99);
