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
  script_oid("1.3.6.1.4.1.25623.1.0.817357");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0648", "CVE-2020-0664", "CVE-2020-0718", "CVE-2020-0761",
                "CVE-2020-0766", "CVE-2020-0782", "CVE-2020-0790", "CVE-2020-0836",
                "CVE-2020-0837", "CVE-2020-0838", "CVE-2020-0839", "CVE-2020-0856",
                "CVE-2020-0870", "CVE-2020-0875", "CVE-2020-0878", "CVE-2020-0886",
                "CVE-2020-0904", "CVE-2020-0908", "CVE-2020-0911", "CVE-2020-0912",
                "CVE-2020-0914", "CVE-2020-0921", "CVE-2020-0922", "CVE-2020-0941",
                "CVE-2020-0951", "CVE-2020-0997", "CVE-2020-0998", "CVE-2020-1012",
                "CVE-2020-1013", "CVE-2020-1030", "CVE-2020-1031", "CVE-2020-1034",
                "CVE-2020-1038", "CVE-2020-1039", "CVE-2020-1052", "CVE-2020-1053",
                "CVE-2020-1057", "CVE-2020-1074", "CVE-2020-1083", "CVE-2020-1091",
                "CVE-2020-1097", "CVE-2020-1115", "CVE-2020-1129", "CVE-2020-1130",
                "CVE-2020-1133", "CVE-2020-1146", "CVE-2020-1152", "CVE-2020-1172",
                "CVE-2020-1180", "CVE-2020-1228", "CVE-2020-1245", "CVE-2020-1250",
                "CVE-2020-1252", "CVE-2020-1256", "CVE-2020-1285", "CVE-2020-1308",
                "CVE-2020-1376", "CVE-2020-1471", "CVE-2020-1491", "CVE-2020-1508",
                "CVE-2020-1559", "CVE-2020-1589", "CVE-2020-1593", "CVE-2020-1596",
                "CVE-2020-1598", "CVE-2020-16854");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4577015)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4577015");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - when Microsoft Windows CloudExperienceHost fails to check COM objects.

  - when the Windows RSoP Service Application improperly handles memory.

  - when Active Directory integrated DNS (ADIDNS) mishandles objects in memory.

  - in how splwow64.exe handles certain calls.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privilges, conduct DoS condition, bypass security restrictions
  and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4577015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Ntoskrnl.exe");
if(!dllVer)
  exit(0);

if(version_in_range(version:dllVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.3929")) {
  report = report_fixed_ver(file_checked:sysPath + "\Ntoskrnl.exe",
                            file_version:dllVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.3929");
  security_message(data:report);
  exit(0);
}
exit(99);
