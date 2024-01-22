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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818523");
  script_version("2023-10-20T16:09:12+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2013-0340", "CVE-2021-22925", "CVE-2021-30811", "CVE-2021-30813",
                "CVE-2021-30819", "CVE-2021-30827", "CVE-2021-30828", "CVE-2021-30829",
                "CVE-2021-30830", "CVE-2021-30832", "CVE-2021-30834", "CVE-2021-30835",
                "CVE-2021-30838", "CVE-2021-30841", "CVE-2021-30842", "CVE-2021-30843",
                "CVE-2021-30844", "CVE-2021-30845", "CVE-2021-30847", "CVE-2021-30850",
                "CVE-2021-30853", "CVE-2021-30855", "CVE-2021-30857", "CVE-2021-30858",
                "CVE-2021-30859", "CVE-2021-30860", "CVE-2021-30864", "CVE-2021-30865",
                "CVE-2021-30925", "CVE-2021-30928", "CVE-2021-30933", "CVE-2021-31010");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-25 16:49:00 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"creation_date", value:"2021-09-14 18:07:04 +0530 (Tue, 14 Sep 2021)");
  script_name("Apple MacOSX Security Update (HT212804)");

  script_tag(name:"summary", value:"Apple Mac OS X is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information
  on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to bypass security restrictions, execute arbitrary code, cause denial of service
  and disclose sensitive information on an affected system.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 11.x through 11.5.2");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 11.6 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT212804");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
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
if(!osVer || osVer !~ "^11\." || "Mac OS X" >!< osName){
  exit(0);
}

if(version_in_range(version:osVer, test_version:"11.0", test_version2:"11.5.2"))
{
  report = report_fixed_ver(installed_version:osVer, fixed_version:"11.6");
  security_message(data:report);
  exit(0);
}

exit(99);
