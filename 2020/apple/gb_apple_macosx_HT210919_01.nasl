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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.816617");
  script_version("2023-10-20T16:09:12+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-3842", "CVE-2020-3871", "CVE-2020-3827", "CVE-2020-3843",
                "CVE-2019-18634", "CVE-2019-11043", "CVE-2020-3829", "CVE-2020-3826",
                "CVE-2020-3870", "CVE-2020-3878", "CVE-2020-3838", "CVE-2020-3836",
                "CVE-2020-3835", "CVE-2020-3830", "CVE-2020-3875", "CVE-2020-3856",
                "CVE-2020-3853");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-01-29 14:38:19 +0530 (Wed, 29 Jan 2020)");
  script_name("Apple Mac OS X Security Update (HT210919 - 01)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues related to improper memory handling.

  - A buffer overflow issue related to improper memory handling.

  - Multiple out-of-bounds read errors related to improper bounds checking and
    input validation.

  - An improper permissions logic.

  - An access issue related to improper memory management.

  - A validation issue existed in the handling of symlinks.

  - A validation issue related to insufficient input sanitization.

  - A type confusion issue related to improper memory handling.");

  script_tag(name:"impact", value:"Successful exploitation allows attackers
  to execute arbitrary code with kernel privileges, cause unexpected system
  termination or corrupt kernel memory, gain elevated privileges, determine
  kernel memory layout, access restricted files and overwrite arbitrary files.");

  script_tag(name:"affected", value:"Apple Mac OS X versions,
  10.13.x through 10.13.6, 10.14.x through 10.14.6, 10.15.x through 10.15.2");

  script_tag(name:"solution", value:"Apply Security Update 2020-001 for 10.13.x,
  and 10.14.x and upgrade to Apple Mac OS X 10.15.3 or later for 10.15.x.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210919");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.1[345]" || "Mac OS X" >!< osName)
  exit(0);

buildVer = get_kb_item("ssh/login/osx_build");

if(osVer =~ "^10\.13") {
  if(version_in_range(version:osVer, test_version:"10.13", test_version2:"10.13.5")) {
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.13.6")
  {
    if(version_is_less(version:buildVer, test_version:"17G11023")) {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

if(osVer =~ "^10\.14") {
  if(version_in_range(version:osVer, test_version:"10.14", test_version2:"10.14.5")) {
    fix = "Upgrade to latest OS release and apply patch from vendor";
  }

  else if(osVer == "10.14.6") {
    if(version_is_less(version:buildVer, test_version:"18G3020")) {
      fix = "Apply patch from vendor";
      osVer = osVer + " Build " + buildVer;
    }
  }
}

else if(version_in_range(version:osVer, test_version:"10.15", test_version2:"10.15.2")) {
  fix = "10.15.3";
}

if(fix) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:fix);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
