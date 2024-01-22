# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813645");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-8282", "CVE-2018-0949", "CVE-2018-8206", "CVE-2018-8242",
                "CVE-2018-8287", "CVE-2018-8288", "CVE-2018-8291", "CVE-2018-8296",
                "CVE-2018-8304", "CVE-2018-8307", "CVE-2018-8308", "CVE-2018-8309",
                "CVE-2018-8314", "CVE-2018-3665");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-07-11 09:15:58 +0530 (Wed, 11 Jul 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4338818)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4338818");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - When Internet Explorer improperly accesses objects in memory.

  - When Windows improperly handles File Transfer Protocol (FTP) connections.

  - When the scripting engine improperly handles objects in memory in Internet
    Explorer.

  - When Windows kernel-mode driver fails to properly handle objects in memory.

  - When Windows Domain Name System (DNS) DNSAPI.dll fails to properly handle
    DNS responses.

  - When Microsoft WordPad improperly handles embedded OLE objects.

  - When Windows fails a check, allowing a sandbox escape.

  - Involving side channel speculative execution, known as Lazy FP State Restore.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass security, cause a target system to stop responding, execute arbitrary
  code in the context of the current user and elevate privileges on an affected
  system.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4338818");
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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Kernel32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24168"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Kernel32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24168");
  security_message(data:report);
  exit(0);
}
exit(99);
