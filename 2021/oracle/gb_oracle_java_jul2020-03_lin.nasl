# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.118167");
  script_version("2021-12-21T05:52:49+0000");
  script_cve_id("CVE-2020-14583", "CVE-2020-14593", "CVE-2020-14621", "CVE-2020-14577");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-12-21 05:52:49 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-10 16:15:00 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2021-08-25 09:18:34 +0200 (Wed, 25 Aug 2021)");
  script_name("Oracle Java SE Security Updates(jul2020) 03 - Linux");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple security vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in components
  Libraries, 2D, JAXP and JSSE.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to have an
  impact on confidentiality, integrity and availability.");

  script_tag(name:"affected", value:"Oracle Java SE version 7u261 (1.7.0.261) and earlier, 8u251
  (1.8.0.251) and earlier, 11.0.7 and earlier, 14.0.1 and earlier on Linux.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujul2020.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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

if( version_in_range( version:vers, test_version:"1.7.0", test_version2:"1.7.0.261" ) ||
   version_in_range( version:vers, test_version:"1.8.0", test_version2:"1.8.0.251" ) ||
   version_in_range( version:vers, test_version:"11.0", test_version2:"11.0.7" ) ||
   version_in_range( version:vers, test_version:"14.0", test_version2:"14.0.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"Apply the patch", install_path:path );
  security_message( data:report );
  exit( 0 );
}

exit( 99 );
