###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4041671)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811861");
  script_version("2022-04-13T11:57:07+0000");
  script_cve_id("CVE-2017-11784", "CVE-2017-11785");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 11:57:07 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-10-20 13:07:00 +0000 (Fri, 20 Oct 2017)");
  script_tag(name:"creation_date", value:"2017-10-11 10:11:55 +0530 (Wed, 11 Oct 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4041671)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4041671.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to Kernel Address
  Space Layout Randomization (ASLR) bypass errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  an attacker who successfully exploited the vulnerability to retrieve the
  memory address of a kernel object. To exploit the vulnerability, an attacker
  would have to log on to an affected system and run a specially crafted
  application.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4041671");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101147");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101149");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"advapi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.0.6002.24202"))
{
  report = 'File checked:     ' + sysPath + "\advapi32.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range: Less than 6.0.6002.24202\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
