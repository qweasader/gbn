# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811165");
  script_version("2023-07-14T16:09:27+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0193", "CVE-2017-8473", "CVE-2017-8474", "CVE-2017-8475",
                "CVE-2017-8527", "CVE-2017-8528", "CVE-2017-0282", "CVE-2017-8476",
                "CVE-2017-8477", "CVE-2017-8531", "CVE-2017-0283", "CVE-2017-0284",
                "CVE-2017-8478", "CVE-2017-8479", "CVE-2017-8532", "CVE-2017-8533",
                "CVE-2017-0285", "CVE-2017-0287", "CVE-2017-8480", "CVE-2017-8481",
                "CVE-2017-8543", "CVE-2017-0288", "CVE-2017-0289", "CVE-2017-8482",
                "CVE-2017-8483", "CVE-2017-8544", "CVE-2017-0291", "CVE-2017-0292",
                "CVE-2017-8484", "CVE-2017-8485", "CVE-2017-8553", "CVE-2017-0294",
                "CVE-2017-0296", "CVE-2017-8488", "CVE-2017-8489", "CVE-2017-8490",
                "CVE-2017-0297", "CVE-2017-0298", "CVE-2017-0299", "CVE-2017-8491",
                "CVE-2017-8492", "CVE-2017-0300", "CVE-2017-8460", "CVE-2017-8493",
                "CVE-2017-8462", "CVE-2017-8464", "CVE-2017-8469", "CVE-2017-8470",
                "CVE-2017-8471", "CVE-2017-8465", "CVE-2017-8466", "CVE-2017-8468",
                "CVE-2017-8554");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-06-14 10:42:25 +0530 (Wed, 14 Jun 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4022717)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4022717");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This security update includes quality
  improvements.

  - Addressed issue where, after installing KB3170455 (MS16-087), users have
    difficulty importing printer drivers and get errors with error code 0x80070bcb.

  - Addressed a rare issue where mouse input can cease to function. The mouse
    pointer may continue to move, but movements and clicks produce no response other
    than a beeping noise.

  - Addressed issue where printing a document using a 32-bit application can crash a
    Print Server in a call to nt!MiGetVadWakeList.

  - Addressed issue where an unsupported hardware notification is shown and Windows
    Updates not scanning, for systems using the AMD Carrizo DDR4 processor or
    Windows Server 2012 R2 systems using Xeon E3V6 processor.

  - Security updates to Microsoft Windows PDF, Windows shell, Windows Kernel,
    Microsoft Graphics Component, Microsoft Uniscribe, Microsoft Scripting Engine,
    Windows COM, and Windows Kernel-Mode Drivers. For more information about the
    security vulnerabilities resolved, please refer to the Security Update Guide.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to gain the same user rights as the current user. If the current user is
  logged on with administrative user rights, an attacker who successfully exploited the
  vulnerability could take control of an affected system. An attacker could then install
  programs. View, change, or delete data, or create new accounts with full user rights.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4022717");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98902");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98853");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98933");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98949");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98903");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98819");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98920");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98918");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98820");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98914");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98923");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98929");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98836");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98940");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98837");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98865");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98840");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98870");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98900");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98818");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98844");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98846");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

fileVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.18698"))
{
  report = 'File checked:     ' + sysPath + "\Win32k.sys" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 6.3.9600.18698\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
