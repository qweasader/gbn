# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815773");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0655", "CVE-2020-0657", "CVE-2020-0658", "CVE-2020-0660",
                "CVE-2020-0662", "CVE-2020-0665", "CVE-2020-0666", "CVE-2020-0667",
                "CVE-2020-0668", "CVE-2020-0673", "CVE-2020-0674", "CVE-2020-0675",
                "CVE-2020-0676", "CVE-2020-0677", "CVE-2020-0678", "CVE-2020-0679",
                "CVE-2020-0680", "CVE-2020-0681", "CVE-2020-0682", "CVE-2020-0683",
                "CVE-2020-0686", "CVE-2020-0691", "CVE-2020-0698", "CVE-2020-0705",
                "CVE-2020-0706", "CVE-2020-0707", "CVE-2020-0708", "CVE-2020-0715",
                "CVE-2020-0716", "CVE-2020-0719", "CVE-2020-0720", "CVE-2020-0721",
                "CVE-2020-0722", "CVE-2020-0723", "CVE-2020-0724", "CVE-2020-0725",
                "CVE-2020-0726", "CVE-2020-0729", "CVE-2020-0730", "CVE-2020-0731",
                "CVE-2020-0734", "CVE-2020-0735", "CVE-2020-0737", "CVE-2020-0738",
                "CVE-2020-0744", "CVE-2020-0745", "CVE-2020-0748", "CVE-2020-0752",
                "CVE-2020-0753", "CVE-2020-0754", "CVE-2020-0755", "CVE-2020-0756",
                "CVE-2020-0817", "CVE-2020-0818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-13 18:11:00 +0000 (Thu, 13 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-12 12:40:36 +0530 (Wed, 12 Feb 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4537821)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4537821");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Common Log File System (CLFS) driver fails to properly handle objects
    in memory.

  - Windows Search Indexer improperly handles objects in memory.

  - Cryptography Next Generation (CNG) service improperly handles objects in memory.

  - Windows Error Reporting manager improperly handles hard links.

  - Windows Function Discovery Service improperly handles objects in memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code, elevate privileges, disclose sensitive information and
  cause denial of service.");

  script_tag(name:"affected", value:"- Microsoft Windows 8.1 for 32-bit/x64-based systems

  - Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4537821");
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

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

sysVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(!sysVer)
  exit(0);

if(version_is_less(version:sysVer, test_version:"6.3.9600.19630")) {
  report = report_fixed_ver(file_checked:sysPath + "\Win32k.sys",
                            file_version:sysVer, vulnerable_range:"Less than 6.3.9600.19630");
  security_message(data:report);
  exit(0);
}

exit(99);
