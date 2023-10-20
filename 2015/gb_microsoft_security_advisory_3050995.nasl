# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805507");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-25 18:58:02 +0530 (Wed, 25 Mar 2015)");
  script_name("Microsoft Digital Certificates Security Advisory (3050995)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (3050995)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to MCS Holdings which
  improperly issued a subordinate CA certificate");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to spoof content, perform phishing attacks, or perform
  man-in-the-middle attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 2003 x32/x64 Service Pack 2 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://support.microsoft.com/en-us/kb/3050995");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/3050995");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

##For Windows Vista, Windows 7, Windows Server 2008, or Windows Server 2008 R2
##systems will be automatically updated by updater of revoked certificates .

##For win2003
if(hotfix_check_sp(win2003:3, win2003x64:3) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Advpack.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if((version_is_less(version:dllVer, test_version:"7.0.5489.0"))){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
