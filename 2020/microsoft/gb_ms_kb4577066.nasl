# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817363");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0648", "CVE-2020-0664", "CVE-2020-0718", "CVE-2020-0761",
                "CVE-2020-0782", "CVE-2020-0790", "CVE-2020-0836", "CVE-2020-0838",
                "CVE-2020-0856", "CVE-2020-0875", "CVE-2020-0878", "CVE-2020-0886",
                "CVE-2020-0911", "CVE-2020-0912", "CVE-2020-0921", "CVE-2020-0922",
                "CVE-2020-0941", "CVE-2020-0998", "CVE-2020-1012", "CVE-2020-1013",
                "CVE-2020-1030", "CVE-2020-1031", "CVE-2020-1033", "CVE-2020-1034",
                "CVE-2020-1038", "CVE-2020-1039", "CVE-2020-1052", "CVE-2020-1074",
                "CVE-2020-1083", "CVE-2020-1091", "CVE-2020-1097", "CVE-2020-1115",
                "CVE-2020-1152", "CVE-2020-1228", "CVE-2020-1245", "CVE-2020-1250",
                "CVE-2020-1252", "CVE-2020-1256", "CVE-2020-1285", "CVE-2020-1376",
                "CVE-2020-1491", "CVE-2020-1508", "CVE-2020-1559", "CVE-2020-1589",
                "CVE-2020-1593", "CVE-2020-1596", "CVE-2020-1598", "CVE-2020-16854");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-09 09:00:21 +0530 (Wed, 09 Sep 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4577066)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4577066");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - in the way that Microsoft COM for Windows handles objects in memory.

  - when the Windows RSoP Service Application improperly handles memory.

  - when Active Directory integrated DNS (ADIDNS) mishandles objects in memory.

  - in how splwow64.exe handles certain calls.

  - when the win32k component improperly provides kernel information.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges, conduct DoS condition and disclose
  sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4577066");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
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

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Win32k.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.3.9600.19815"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Win32k.sys",
                            file_version:fileVer, vulnerable_range:"Less than 6.3.9600.19815");
  security_message(data:report);
  exit(0);
}
exit(99);
