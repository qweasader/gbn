# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812768");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-0742", "CVE-2018-0757", "CVE-2018-0820", "CVE-2018-0825",
                "CVE-2018-0829", "CVE-2018-0830", "CVE-2018-0832", "CVE-2018-0833",
                "CVE-2018-0840", "CVE-2018-0842", "CVE-2018-0844", "CVE-2018-0846",
                "CVE-2018-0847", "CVE-2018-0866");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-02-14 11:19:08 +0530 (Wed, 14 Feb 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4074594)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4074594");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The scripting engine fails to properly handles objects in memory in
    microsoft browsers.

  - The windows kernel fails to properly handle objects in memory.

  - The Windows Common Log File System (CLFS) driver improperly handles
    objects in memory.

  - The VBScript improperly discloses the contents of its memory, which could
    provide an attacker with information to further compromise the user's
    computer or data.

  - An improper implementation of the Microsoft Server Message Block 2.

  - Microsoft has deprecated the Document Signing functionality in XPS Viewer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker who successfully exploited the vulnerability gain the same
  user rights as the current user, run arbitrary code in kernel mode, obtain
  information to further compromise the user's system, cause the affected system
  to stop responding until it is manually restarted, spoof content, perform
  phishing attacks, or otherwise manipulate content of a document.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4074594");
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

if(version_is_less(version:fileVer, test_version:"11.0.9600.18921"))
{
  report = report_fixed_ver(file_checked:sysPath + "\urlmon.dll",
                            file_version:fileVer, vulnerable_range:"Less than 11.0.9600.18921");
  security_message(data:report);
  exit(0);
}
exit(0);
