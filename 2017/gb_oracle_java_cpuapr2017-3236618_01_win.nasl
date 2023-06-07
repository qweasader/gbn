# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.810745");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-3514", "CVE-2017-3526", "CVE-2017-3509", "CVE-2017-3533",
                "CVE-2017-3544", "CVE-2017-3539");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-04-19 12:58:08 +0530 (Wed, 19 Apr 2017)");
  script_name("Oracle Java SE Security Updates (cpuapr2017-3236618) 01 - Windows");

  script_tag(name:"summary", value:"Oracle Java SE is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in 'AWT', 'JCE', 'JAXP', 'Networking', 'Security' and
  'Deployment' sub-components.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to cause some unspecified impacts.");

  script_tag(name:"affected", value:"Oracle Java SE version 1.6.0.141 and
  earlier, 1.7.0.131 and earlier, 1.8.0.121 and earlier on Windows.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97733");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97745");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97752");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixJAVA");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_portable_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:oracle:jre", "cpe:/a:sun:jre");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^1\.[6-8]\.") {
  if(version_in_range(version:vers, test_version:"1.6.0", test_version2:"1.6.0.141") ||
     version_in_range(version:vers, test_version:"1.7.0", test_version2:"1.7.0.131") ||
     version_in_range(version:vers, test_version:"1.8.0", test_version2:"1.8.0.121")) {
    report = report_fixed_ver(installed_version:vers, fixed_version: "Apply the patch", install_path:path);
    security_message(data:report);
    exit(0);
  }
}
