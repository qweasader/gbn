# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804493");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-4115");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-10-15 09:05:23 +0530 (Wed, 15 Oct 2014)");
  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Microsoft Windows FAT32 Disk Partition Driver Privilege Escalation Vulnerability (2998579)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-063.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a buffer under-allocation
  error within the FASTFAT driver and can be exploited to cause a function to
  write data in otherwise reserved memory.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  local users to gain escalated privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows Vista x32/x64 Service Pack 2 and prior

  - Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2998579");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70343");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS14-063");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

win32SysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\drivers\Fastfat.sys");
if(!win32SysVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"5.2.3790.5425")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Vista 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_is_less(version:win32SysVer, test_version:"6.0.6002.19176") ||
     version_in_range(version:win32SysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23479")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
