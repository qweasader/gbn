# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805922");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2361", "CVE-2015-2362");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-07-15 13:50:29 +0530 (Wed, 15 Jul 2015)");
  script_name("Microsoft Windows Hyper-V Remote Code Execution Vulnerability (3072000)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-068.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in how Hyper-V handles packet size memory initialization in guest
    virtual machines.

  - An error in how Hyper-V initializes system data structures in guest virtual
    machines.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary code on affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 8 x64

  - Microsoft Windows 8.1 x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows Server 2008 x64 Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3046359");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-068");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(hotfix_check_sp(win2008r2:2, win8x64:1, win2012:1, win2012R2:1,
                   win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"System32\Vmicvss.dll");
dllVer2 = fetch_file_version(sysPath:sysPath, file_name:"System32\drivers\Storvsp.sys");
if(!dllVer && !dllVer2){
  exit(0);
}

if(hotfix_check_sp(win2008r2:2) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"6.1.7601.18844") ||
     version_in_range(version:dllVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.23044")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win8x64:1, win2012:1) > 0 && dllVer)
{
  if(version_is_less(version:dllVer, test_version:"6.2.9200.17361") ||
     version_in_range(version:dllVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21472")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8.1 and win2012R2
if(hotfix_check_sp(win8_1x64:1, win2012R2:1) > 0)
{
  if((dllVer && version_is_less(version:dllVer, test_version:"6.3.9600.17723"))||
     (dllVer2 && version_is_less(version:dllVer2, test_version:"6.3.9600.17723"))){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
