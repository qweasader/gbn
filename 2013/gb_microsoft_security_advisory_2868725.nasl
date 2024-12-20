# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804142");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-11-14 11:28:18 +0530 (Thu, 14 Nov 2013)");
  script_name("Microsoft RC4 Disabling Security Advisory (2868725)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
advisory (2868725).");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"insight", value:"The flaw is due to security issue in RC4 stream cipher used in Transport
Layer Security(TLS) and Secure Socket Layer(SSL).");
  script_tag(name:"affected", value:"- Microsoft Windows 7 x32/x64 Service Pack 1 and prior

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior

  - Microsoft Windows 8 x32/x64

  - Microsoft Windows Server 2012");
  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to perform man-in-the-middle
attacks and recover plain text from encrypted sessions.");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2868725");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/advisory/2868725");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1, win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

schannelVer = fetch_file_version(sysPath:sysPath, file_name:"system32\schannel.dll");
if(!schannelVer){
  exit(0);
}

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_is_less(version:schannelVer, test_version:"6.1.7601.18270") ||
     version_in_range(version:schannelVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22464")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_is_less(version:schannelVer, test_version:"6.2.9200.16722") ||
     version_in_range(version:schannelVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20831")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
