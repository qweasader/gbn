# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812958");
  script_version("2023-07-20T05:05:18+0000");
  script_cve_id("CVE-2018-7249", "CVE-2018-7250");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-22 13:26:00 +0000 (Thu, 22 Mar 2018)");
  script_tag(name:"creation_date", value:"2018-02-28 14:37:31 +0530 (Wed, 28 Feb 2018)");
  script_name("Microsoft Windows Information Disclosure and Code Execution Vulnerabilities (KB3086255)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB3086255");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An uninitialized kernel pool allocation in IOCTL 0xCA002813.

  - Two carefully timed calls to IOCTL 0xCA002813 can cause a race condition that
    leads to a use-after-free.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the kernel user space and leak 16 bits of uninitialized
  kernel PagedPool data.");

  script_tag(name:"affected", value:"- Microsoft Windows 8/8.1 x32/x64

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3086255");
  script_xref(name:"URL", value:"https://github.com/Elvin9/NotSecDrv/blob/master/README.md");
  script_xref(name:"URL", value:"https://github.com/Elvin9/SecDrvPoolLeak/blob/master/README.md");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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

if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"Drivers\Secdrv.sys");
if(!dllVer){
  exit(0);
}

if(version_is_less(version:dllVer, test_version:"4.3.86.0"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Drivers\Secdrv.sys",
           file_version:dllVer, vulnerable_range:"Less than 4.3.86.0");
  security_message(data:report);
  exit(0);
}
exit(0);
