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
  script_oid("1.3.6.1.4.1.25623.1.0.816879");
  script_version("2021-08-11T08:56:08+0000");
  script_cve_id("CVE-2020-0760");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-17 19:11:00 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-16 10:25:30 +0530 (Thu, 16 Apr 2020)");
  script_name("Microsoft Outlook 2010 Service Pack 2 Remote Code Execution Vulnerability (KB4484284)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4484284");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A remote code execution vulnerability exists
  when Microsoft Office improperly loads arbitrary type libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft Outlook 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4484284");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outlook/Version");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

outlookVer = get_kb_item("SMB/Office/Outlook/Version");
if(!outlookVer|| outlookVer !~ "^14\."){
  exit(0);
}

outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\OUTLOOK.EXE", item:"Path");
if(!outlookFile){
  exit(0);
}

outlookVer = fetch_file_version(sysPath:outlookFile, file_name:"outlook.exe");
if(!outlookVer){
  exit(0);
}

if(version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7248.4999")){
  report = report_fixed_ver(file_checked: outlookFile + "outlook.exe",
                            file_version:outlookVer, vulnerable_range:"14.0 - 14.0.7248.4999");
  security_message(data:report);
  exit(0);
}
exit(99);
