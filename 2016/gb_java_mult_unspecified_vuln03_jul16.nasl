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

CPE = "cpe:/a:oracle:jre";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808623");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2016-3552", "CVE-2016-3587", "CVE-2016-3598", "CVE-2016-3610");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 12:30:00 +0000 (Tue, 08 Sep 2020)");
  script_tag(name:"creation_date", value:"2016-07-25 11:28:15 +0530 (Mon, 25 Jul 2016)");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities-03 July 2016 (Windows)");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A flaw in the Hotspot component.

  - A flaw in the JavaFX component.

  - A flaw in the Install component.

  - A flaw in the Libraries component");

  script_tag(name:"impact", value:"Successful exploitation will allow remote user
  to access and modify data on the target system, can cause denial of service
  conditions on the target system, a remote or local user can obtain elevated
  privileges on the  target system, also a local user can modify data on the
  target system.");

  script_tag(name:"affected", value:"Oracle Java SE 8 update 92 and prior
  on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpujul2016-2881720.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91904");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/91930");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);

jreVer = infos['version'];
jrePath = infos['location'];

if(jreVer =~ "^(1\.8)")
{
  if(version_in_range(version:jreVer, test_version:"1.8.0", test_version2:"1.8.0.92"))
  {
    report = report_fixed_ver(installed_version:jreVer, fixed_version:"Apply the patch", install_path:jrePath);
    security_message(data:report);
    exit(0);
  }
}
