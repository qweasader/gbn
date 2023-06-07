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
  script_oid("1.3.6.1.4.1.25623.1.0.826624");
  script_version("2022-11-10T10:12:04+0000");
  script_cve_id("CVE-2022-41060", "CVE-2022-41061", "CVE-2022-41063", "CVE-2022-41103",
                "CVE-2022-41104", "CVE-2022-41105", "CVE-2022-41106", "CVE-2022-41107");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-11-10 10:12:04 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-09 09:27:51 +0530 (Wed, 09 Nov 2022)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities - Nov22");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run update November 2022");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple
  unspecified errors in Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, disclose information and bypass security feature
  on an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2210 (Build 15726.20202)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.15726.20202")){
    fix = "Version 2210 (Build 15726.20202)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2208 (Build 15601.20230)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.15601.20286")){
    fix = "Version 2208 (Build 15601.20286)";
  }
}

## Semi-Annual Enterprise Channel: Version 2202 (Build 14931.20764)
## Semi-Annual Enterprise Channel: Version 2108 (Build 14326.21186)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14326.21200")){
    fix = "2108 (Build 14326.21200)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.14931.0", test_version2:"16.0.14931.20806")){
    fix = "2202 (Build 14931.20806)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
