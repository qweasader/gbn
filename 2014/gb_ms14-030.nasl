# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802077");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0296");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-11 08:26:33 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Remote Desktop Tampering Vulnerability (2969259)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS14-030.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due Remote Desktop does not use robust encryption for an RDP session.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker gain access to and modify
potentially sensitive RDP information during an active session.");
  script_tag(name:"affected", value:"- Microsoft Windows 8 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 7 x32/x64 Service Pack 1 and prior");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2965788");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67865");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2966034");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-030");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win8:1, win8x64:1,
                   win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Rdpcorets.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.1.7601.18465") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22677") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16911") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21034")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16912") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21034")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Currently not supporting for Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  if(version_in_range(version:sysVer, test_version:"6.3.9600.16000", test_version2:"6.3.9600.16662") ||
     version_in_range(version:sysVer, test_version:"6.3.9600.17000", test_version2:"6.3.9600.17115")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
