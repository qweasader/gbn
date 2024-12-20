# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812865");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-0870", "CVE-2018-0887", "CVE-2018-8116", "CVE-2018-0957",
                "CVE-2018-0960", "CVE-2018-0967", "CVE-2018-0968", "CVE-2018-0969",
                "CVE-2018-0970", "CVE-2018-0971", "CVE-2018-0972", "CVE-2018-0973",
                "CVE-2018-0974", "CVE-2018-0975", "CVE-2018-0976", "CVE-2018-0981",
                "CVE-2018-0987", "CVE-2018-0988", "CVE-2018-0989", "CVE-2018-0991",
                "CVE-2018-1003", "CVE-2018-1004", "CVE-2018-1008", "CVE-2018-1009",
                "CVE-2018-1010", "CVE-2018-1012", "CVE-2018-1013", "CVE-2018-1015",
                "CVE-2018-1016", "CVE-2018-1018", "CVE-2018-1020", "CVE-2018-0996",
                "CVE-2018-0997", "CVE-2018-1000", "CVE-2018-1001");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-04-11 09:29:12 +0530 (Wed, 11 Apr 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4093114)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4093114");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - When the Windows font library improperly handles specially crafted embedded
    fonts.

  - When Internet Explorer improperly accesses objects in memory.

  - When the Windows kernel fails to properly initialize a memory address.

  - When the scripting engine does not properly handle objects in memory in
    Internet Explorer.

  - In Windows Adobe Type Manager Font Driver (ATMFD).

  - In the Windows kernel that could allow an attacker to retrieve information
    that could lead to a Kernel Address Space Layout Randomization (ASLR) bypass.

  - In the way that Windows SNMP Service handles malformed SNMP traps.

  - In the way that the VBScript engine handles objects in memory.

  - When Windows improperly handles objects in memory and incorrectly maps kernel
    memory.

  - In the way that Windows handles objects in memory.

  - In Remote Desktop Protocol (RDP) when an attacker connects to the target
    system using RDP and sends specially crafted requests.

  - When Windows Hyper-V on a host operating system fails to properly validate
    input from an authenticated user on a guest operating system.

  - In the Microsoft JET Database Engine that could allow remote code execution on
    an affected system.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to take control of the affected system, obtain information to further compromise
  the user's system, execute arbitrary code, retrieve the memory address of a
  kernel object, cause a target system to stop responding.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4093114");
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

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"urlmon.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.18978"))
{
  report = report_fixed_ver(file_checked:sysPath + "\urlmon.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.18978");
  security_message(data:report);
  exit(0);
}
exit(0);
