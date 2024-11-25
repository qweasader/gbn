# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815742");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-0601", "CVE-2020-0607", "CVE-2020-0612", "CVE-2020-0615",
                "CVE-2020-0617", "CVE-2020-0623", "CVE-2020-0608", "CVE-2020-0609",
                "CVE-2020-0610", "CVE-2020-0611", "CVE-2020-0614", "CVE-2020-0613",
                "CVE-2020-0620", "CVE-2020-0622", "CVE-2020-0625", "CVE-2020-0626",
                "CVE-2020-0627", "CVE-2020-0628", "CVE-2020-0629", "CVE-2020-0630",
                "CVE-2020-0631", "CVE-2020-0632", "CVE-2020-0633", "CVE-2020-0634",
                "CVE-2020-0635", "CVE-2020-0637", "CVE-2020-0639", "CVE-2020-0644",
                "CVE-2020-0641", "CVE-2020-0642", "CVE-2020-0643", "CVE-2020-0606",
                "CVE-2020-0646", "CVE-2020-0640", "CVE-2020-0605");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-17 21:16:00 +0000 (Fri, 17 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-15 08:57:53 +0530 (Wed, 15 Jan 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4534271)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4534271");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Common Log File System (CLFS) driver when it fails to properly
    handle objects in memory.

  - Windows Search Indexer improperly handles objects in memory.

  - win32k component improperly provides kernel information.

  - Microsoft Windows Graphics Component improperly handles objects in
    memory.

  - Microsoft Windows implements predictable memory section names.

  - Windows Media Service allows file creation in arbitrary locations.

  - Internet Explorer improperly accesses objects in memory.

  - Windows Graphics Device Interface Plus (GDI+) improperly handles objects
    in memory.

  - Remote Desktop Web Access improperly handles credential information.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code, elevate privileges, disclose sensitive
  information, conduct denial of service and spoofing attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4534271");
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

if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"User32.dll");
if(!dllVer)
  exit(0);

if(version_in_range(version:dllVer, test_version:"10.0.14393.0", test_version2:"10.0.14393.3442")) {
  report = report_fixed_ver(file_checked:sysPath + "\User32.dll",
                            file_version:dllVer, vulnerable_range:"10.0.14393.0 - 10.0.14393.3442");
  security_message(data:report);
  exit(0);
}

exit(99);
