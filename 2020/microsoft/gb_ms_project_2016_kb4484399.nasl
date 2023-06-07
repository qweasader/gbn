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

CPE = "cpe:/a:microsoft:project";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817053");
  script_version("2021-08-11T12:01:46+0000");
  script_cve_id("CVE-2020-1322");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-08-11 12:01:46 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-16 13:16:00 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-10 11:16:25 +0530 (Wed, 10 Jun 2020)");
  script_name("Microsoft Project 2016 Information Disclosure Vulnerability (KB4484399)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4484399");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An information disclosure vulnerability exists
  when Microsoft Project reads out of bound memory due to an uninitialized variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to view out of bound memory that potentially could contain sensitive information.");

  script_tag(name:"affected", value:"Microsoft Project 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4484399");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_project_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Microsoft/Project/Win/Ver");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
proPath = infos['location'];
if(!proPath || "Did not find install path from registry" >< proPath){
  exit(0);
}

path = proPath + "\Office16";
proVer = fetch_file_version(sysPath:path, file_name:"winproj.exe");
if(!proVer){
  exit(0);
}

if(version_in_range(version:proVer, test_version:"16.0.4900.0", test_version2:"16.0.5017.0999"))
{
  report = report_fixed_ver(file_checked:path + "\winproj.exe",
                            file_version:proVer, vulnerable_range:"16.0.4900.0 - 16.0.5017.0999");
  security_message(data:report);
  exit(0);
}
exit(99);
