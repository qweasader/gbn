# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811563");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-0174", "CVE-2017-0250", "CVE-2017-0293", "CVE-2017-8591",
                "CVE-2017-8593", "CVE-2017-8620", "CVE-2017-8624", "CVE-2017-8633",
                "CVE-2017-8664", "CVE-2017-8666", "CVE-2017-8668");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-15 17:24:00 +0000 (Tue, 15 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-08-09 12:06:29 +0530 (Wed, 09 Aug 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4034672)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4034672");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - The Win32k component fails to properly handle objects in memory.

  - Windows Input Method Editor (IME) when IME improperly handles parameters in
    a method of a DCOM class.

  - An error in Windows Error Reporting (WER).

  - Windows Hyper-V on a host server fails to properly validate input from an
    authenticated user on a guest operating system.

  - Microsoft JET Database Engine that could allow remote code execution on
    an affected system.

  - Windows Search improperly handles objects in memory memory.

  - Microsoft Windows PDF Library improperly handles objects in memory.

  - Microsoft Windows improperly handles NetBIOS packets.

  - The win32k component improperly provides kernel information.

  - The Volume Manager Extension Driver component improperly provides
    kernel information.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in kernel mode, instantiate the DCOM class and exploit the
  system even if IME is not enabled, gain access to sensitive information and
  system functionality, take complete control of an affected system, cause denial
  of service condition and further compromise the user's system.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2012 R2

  - Microsoft Windows 8.1 for 32-bit/x64");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4034672");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98100");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99430");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100061");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100069");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100085");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100089");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100092");
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

if(hotfix_check_sp(win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"mssrch.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"7.0.9600.18731"))
{
  report = 'File checked:     ' + sysPath + "\mssrch.dll" + '\n' +
           'File version:     ' + fileVer  + '\n' +
           'Vulnerable range:  Less than 7.0.9600.18731\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
