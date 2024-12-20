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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821188");
  script_version("2023-10-19T05:05:21+0000");
  script_cve_id("CVE-2022-34169", "CVE-2022-21541", "CVE-2022-21540", "CVE-2022-21549");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-30 15:03:00 +0000 (Tue, 30 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-07-25 21:05:18 +0530 (Mon, 25 Jul 2022)");
  script_name("Oracle Java SE Security Update (jul2022) - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to unspecified
  errors in 'Libraries', 'JAXP' and 'Hotspot' components.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to have an impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle Java SE version 7u343 (1.7.0.343)
  and earlier, 8u333 (1.8.0.333) and earlier, 11.x through 11.0.15.1,
  17.x through 17.0.3.1, 18.x through 18.0.1.1 on Linux.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2022.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Oracle/Java/JDK_or_JRE/Linux/detected");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:oracle:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.343") ||
   version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.333") ||
   version_in_range(version:vers, test_version:"11.0", test_version2:"11.0.15.1") ||
   version_in_range(version:vers, test_version:"17.0", test_version2:"17.0.3.1") ||
   version_in_range(version:vers, test_version:"18.0", test_version2:"18.0.1.1"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
