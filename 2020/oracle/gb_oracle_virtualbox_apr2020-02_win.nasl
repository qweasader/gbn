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

CPE = "cpe:/a:oracle:vm_virtualbox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816847");
  script_version("2021-10-05T11:36:17+0000");
  script_cve_id("CVE-2020-2742", "CVE-2020-2743");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-05 11:36:17 +0000 (Tue, 05 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 14:50:00 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2020-04-15 08:39:55 +0530 (Wed, 15 Apr 2020)");
  script_name("Oracle VirtualBox Security Update (cpuapr2020 - 02) - Windows");

  script_tag(name:"summary", value:"Oracle VM VirtualBox is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors
  in 'Core' component.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"VirtualBox versions prior to 5.2.36, 6.1.x
  prior to 6.1.2 and 6.0.x prior to 6.0.16.");

  script_tag(name:"solution", value:"Update to Oracle VirtualBox version 5.2.36
  or 6.0.16 or 6.1.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixOVIR");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version =~ "^6\.0\." && version_is_less(version:version, test_version:"6.0.16")){
  fix = "6.0.16";
}

else if(version =~ "^6\.1\." && version_is_less(version:version, test_version:"6.1.2")){
  fix = "6.1.2";
}

else if(version_is_less(version:version, test_version:"5.2.36")){
  fix = "5.2.36";
}

if(fix){
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);