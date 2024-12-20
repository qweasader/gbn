# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805092");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-2423");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-08-12 16:44:01 +0530 (Wed, 12 Aug 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Visio Multiple Remote Code Execution Vulnerabilities (3080790)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-081.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws are due to improper handling of files
  in the memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to run arbitrary code in the context of the current user and
  to perform actions in the security context of the current user.");

  script_tag(name:"affected", value:"- Microsoft Visio 2007

  - Microsoft Visio 2010

  - Microsoft Visio 2013");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2965280");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3054876");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3054929");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/MS15-081");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms15-081");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
if(!sysPath){
  exit(0);
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(exeVer && exeVer =~ "^(12|14|15)\..*")
{
   if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6727.4999") ||
      version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7155.4999") ||
      version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4745.999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
