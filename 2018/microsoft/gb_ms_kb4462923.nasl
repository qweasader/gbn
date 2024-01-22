# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814084");
  script_version("2023-11-03T16:10:08+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-8320", "CVE-2018-8330", "CVE-2018-8333", "CVE-2018-8411",
                "CVE-2018-8413", "CVE-2018-8423", "CVE-2018-8432", "CVE-2018-8453",
                "CVE-2018-8460", "CVE-2018-8472", "CVE-2018-8481", "CVE-2018-8482",
                "CVE-2018-8486", "CVE-2018-8489", "CVE-2018-8491", "CVE-2018-8494");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-28 21:39:00 +0000 (Wed, 28 Nov 2018)");
  script_tag(name:"creation_date", value:"2018-10-10 10:22:26 +0530 (Wed, 10 Oct 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4462923)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4462923");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Win32k component fails to properly handle objects in memory.

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Microsoft XML Core Services MSXML parser improperly processes user input.

  - Internet Explorer improperly accesses objects in memory.

  - Filter Manager improperly handles objects in memory.

  - Windows TCP/IP stack improperly handles fragmented IP packets.

  - Windows Media Player improperly discloses file information.

  - Windows Graphics Device Interface (GDI) improperly handles objects in memory.

  - DirectX Graphics Kernel (DXGKRNL) driver improperly handles objects in memory.

  - Windows kernel improperly handles objects in memory.

  - Windows Theme API does not properly decompress files.

  - NTFS improperly checks access.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, bypass security restrictions, gain the same user rights
  as the current user, obtain information to further compromise the user's system,
  improperly discloses file information and escalate privileges.");

  script_tag(name:"affected", value:"- Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4462923");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Gdi32.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.1.7601.24260"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Gdi32.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.1.7601.24260");
  security_message(data:report);
  exit(0);
}
exit(99);
