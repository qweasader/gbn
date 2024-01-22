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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815582");
  script_version("2023-10-20T16:09:12+0000");
  script_cve_id("CVE-2020-0850", "CVE-2020-0851", "CVE-2020-0855", "CVE-2020-0892",
                "CVE-2020-0852");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-04 14:14:00 +0000 (Mon, 04 May 2020)");
  script_tag(name:"creation_date", value:"2020-03-11 12:26:06 +0530 (Wed, 11 Mar 2020)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities Mar20 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update for Microsoft Office 2016 and Office 2019 on Mac OSX according to
  Microsoft security update March 2020");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Flaws are due to Microsoft Excel and Word
  fails to properly handle objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Office 2016 and Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 16.16.20 for Microsoft
  Office 2016 and to version 16.35 for Office 2019. Please see the references
  for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}


include("version_func.inc");
if(!offVer = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(offVer =~ "^1[56]\.")
{
  if(version_is_less(version:offVer, test_version:"16.16.20")){
    fix = "16.16.20";
  }
  else if(version_in_range(version:offVer, test_version:"16.17.0", test_version2:"16.34")){
    fix = "16.35";
  }

  if(fix)
  {
    report = report_fixed_ver(installed_version:offVer, fixed_version:fix);
    security_message(data:report);
    exit(0);
  }
}
exit(0);
