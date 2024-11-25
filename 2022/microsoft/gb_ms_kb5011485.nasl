# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818974");
  script_version("2024-10-10T07:25:31+0000");
  script_cve_id("CVE-2022-21967", "CVE-2022-21975", "CVE-2022-21977", "CVE-2022-21990",
                "CVE-2022-22010", "CVE-2022-23253", "CVE-2022-23278", "CVE-2022-23281",
                "CVE-2022-23283", "CVE-2022-23284", "CVE-2022-23285", "CVE-2022-23286",
                "CVE-2022-23287", "CVE-2022-23288", "CVE-2022-23290", "CVE-2022-23291",
                "CVE-2022-23293", "CVE-2022-23294", "CVE-2022-23296", "CVE-2022-23297",
                "CVE-2022-23298", "CVE-2022-23299", "CVE-2022-24454", "CVE-2022-24455",
                "CVE-2022-24459", "CVE-2022-24460", "CVE-2022-24502", "CVE-2022-24503",
                "CVE-2022-24505", "CVE-2022-24507", "CVE-2022-24525");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-10-10 07:25:31 +0000 (Thu, 10 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-14 17:18:00 +0000 (Mon, 14 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-09 06:00:50 +0530 (Wed, 09 Mar 2022)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5011485)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5011485");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An elevation of privilege vulnerability in Windows DWM Core Library.

  - An elevation of privilege vulnerability in Windows Update Stack.

  - An elevation of privilege vulnerability in Windows CD-ROM Driver.

  - An elevation of privilege vulnerability in Windows Print Spooler.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to elevate privileges, disclose sensitive information, conduct remote code execution,
  bypass security restrictions and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1909 for 32-bit Systems

  - Microsoft Windows 10 Version 1909 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/help/5011485");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.2157"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe",
                            file_version:fileVer, vulnerable_range:"10.0.18362.0 - 10.0.18362.2157");
  security_message(data:report);
  exit(0);
}
exit(99);
