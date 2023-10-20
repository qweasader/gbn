# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814003");
  script_version("2023-07-20T05:05:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2018-5391", "CVE-2018-8271", "CVE-2018-8315", "CVE-2018-8332",
                "CVE-2018-8335", "CVE-2018-8392", "CVE-2018-8393", "CVE-2018-8410",
                "CVE-2018-8419", "CVE-2018-8420", "CVE-2018-8424", "CVE-2018-8433",
                "CVE-2018-8434", "CVE-2018-8438", "CVE-2018-8439", "CVE-2018-8440",
                "CVE-2018-8442", "CVE-2018-8443", "CVE-2018-8444", "CVE-2018-8446",
                "CVE-2018-8447", "CVE-2018-8452", "CVE-2018-8455", "CVE-2018-8457",
                "CVE-2018-8468", "CVE-2018-8470", "CVE-2018-8475");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-09-12 10:20:08 +0530 (Wed, 12 Sep 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4457129)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4457129");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Denial of service vulnerability (named 'FragmentSmack').

  - Windows bowser.sys kernel-mode driver fails to properly handle objects
    in memory.

  - Browser scripting engine improperly handle object types.

  - Windows font library improperly handles specially crafted embedded fonts.

  - SMB improperly handles specially crafted client requests.

  - Microsoft JET Database Engine improperly handles objects in memory.

  - Windows Kernel API improperly handles registry objects in memory.

  - Windows kernel fails to properly initialize a memory address.

  - Microsoft XML Core Services improperly MSXML parser processes user input.

  - Windows GDI component improperly discloses the contents of its memory.

  - Windows Graphics component improperly handles objects in memory.

  - Hyper-V improperly validates guest operating system user input.

  - Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - Windows kernel improperly handles objects in memory.

  - Microsoft Server Message Block 2.0 (SMBv2) server improperly handles certain
    requests.

  - Internet Explorer improperly accesses objects in memory.

  - Scripting engine does not properly handle objects in memory in Microsoft browsers.

  - Windows improperly parses files.

  - Internet Explorer improperly handles script.

  - Windows does not properly handle specially crafted image files.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code in the context of the current user, obtain information
  to further compromise the user's system, gain elevated privileges on a targeted
  system and also cause the affected system to crash.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4457129");
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

if(version_is_less(version:fileVer, test_version:"11.0.9600.19130"))
{
  report = report_fixed_ver(file_checked:sysPath + "\urlmon.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.19130");
  security_message(data:report);
  exit(0);
}
exit(99);
