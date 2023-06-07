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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826503");
  script_version("2022-09-14T10:57:19+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-27942", "CVE-2020-3838", "CVE-2020-8037", "CVE-2020-8284",
                "CVE-2020-8285", "CVE-2020-8286", "CVE-2021-1739", "CVE-2021-1740",
                "CVE-2021-1784", "CVE-2021-1797", "CVE-2021-1808", "CVE-2021-1809",
                "CVE-2021-1810", "CVE-2021-1811", "CVE-2021-1813", "CVE-2021-1824",
                "CVE-2021-1828", "CVE-2021-1832", "CVE-2021-1834", "CVE-2021-1839",
                "CVE-2021-1840", "CVE-2021-1841", "CVE-2021-1843", "CVE-2021-1846",
                "CVE-2021-1847", "CVE-2021-1851", "CVE-2021-1857", "CVE-2021-1858",
                "CVE-2021-1860", "CVE-2021-1868", "CVE-2021-1873", "CVE-2021-1875",
                "CVE-2021-1876", "CVE-2021-1878", "CVE-2021-1881", "CVE-2021-1882",
                "CVE-2021-30652", "CVE-2021-30655", "CVE-2021-30657");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-09-14 10:57:19 +0000 (Wed, 14 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-15 15:35:00 +0000 (Wed, 15 Sep 2021)");
  script_tag(name:"creation_date", value:"2022-09-02 11:24:06 +0530 (Fri, 02 Sep 2022)");
  script_name("Apple MacOSX Security Update (HT212326)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information
  on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions, execute arbitrary code, cause denial of service
  and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.15.x prior to
  10.15.7 Security Update 2021-002 Catalina.");

  script_tag(name:"solution", value:"Apply Security Update 2021-002 for 10.15.x.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212326");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}
include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.15\." || "Mac OS X" >!< osName){
  exit(0);
}

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.15")
{
  if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.6")){
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.15.7")
  {
    if(version_is_less(version:buildVer, test_version:"19H1030"))
    {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}

exit(99);
