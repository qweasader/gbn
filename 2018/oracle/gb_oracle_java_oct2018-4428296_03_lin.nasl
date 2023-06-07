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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814405");
  script_version("2022-06-29T10:11:11+0000");
  # nb: From the vendor advisory: The fix for CVE-2018-13785 also addresses CVE-2018-14048.
  script_cve_id("CVE-2018-3149", "CVE-2018-13785", "CVE-2018-3136", "CVE-2018-3139",
                "CVE-2018-3180", "CVE-2018-14048");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-06-29 10:11:11 +0000 (Wed, 29 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:33:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-10-17 13:00:22 +0530 (Wed, 17 Oct 2018)");
  script_name("Oracle Java SE Security Updates-03 (cpuoct2018) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_lin.nasl");
  script_mandatory_keys("Sun_or_Oracle/Java/JDK_or_JRE/Linux/detected");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpuoct2018.html#AppendixJAVA");
  script_xref(name:"Advisory-ID", value:"cpuoct2018");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Check if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to errors in components 'JNDI',
  'Deployment (libpng)', 'Security', 'Networking' and 'JSSE'.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain elevated
  privileges, cause partial denial of service conditions, partially modify and access data.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0 through 1.6.0.201, 1.7.0 through
  1.7.0.191, 1.8.0 through 1.8.0.181 and 11.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre", "cpe:/a:oracle:jdk", "cpe:/a:sun:jdk");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^(1\.[6-8]|11)") {
  if((version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.191")) ||
     (version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.181")) ||
     (version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.201")) ||
     (version_is_equal(version:vers, test_version:"11"))) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"See reference", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
