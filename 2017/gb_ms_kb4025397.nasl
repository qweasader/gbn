###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Performance Monitor Information Disclosure Vulnerability (KB4025397)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811455");
  script_version("2021-09-16T12:01:45+0000");
  script_cve_id("CVE-2017-0170");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-27 01:29:00 +0000 (Wed, 27 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-07-12 09:53:59 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows Performance Monitor Information Disclosure Vulnerability (KB4025397)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4025397");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in Windows
  Performance Monitor Console when it improperly parses XML input containing
  a reference to an external entity.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to read arbitrary files via an XML external entity (XXE) declaration.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025397");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"perfmon.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.0.6002.19810"))
{
  Vulnerable_range = "Less than 6.0.6002.19810";
  VULN = TRUE ;
}

else if(version_in_range(version:fileVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.24129"))
{
  Vulnerable_range = "6.0.6002.23000 - 6.0.6002.24129";
  VULN = TRUE ;
}

if(VULN)
{
  report = 'File checked:     ' + sysPath + "\perfmon.exe" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: ' + Vulnerable_range + '\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);