# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818011");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-1640", "CVE-2021-24107", "CVE-2021-26411", "CVE-2021-26861",
                "CVE-2021-26862", "CVE-2021-26866", "CVE-2021-26868", "CVE-2021-26869",
                "CVE-2021-26871", "CVE-2021-26872", "CVE-2021-26873", "CVE-2021-26875",
                "CVE-2021-26878", "CVE-2021-26879", "CVE-2021-26881", "CVE-2021-26882",
                "CVE-2021-26884", "CVE-2021-26885", "CVE-2021-26886", "CVE-2021-26898",
                "CVE-2021-26899", "CVE-2021-26901", "CVE-2021-27077");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 17:15:00 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-03-10 14:03:18 +0530 (Wed, 10 Mar 2021)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5000807)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5000807");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in Windows Print Spooler.

  - An error in Windows Event Tracing.

  - An memory corruption flaw in Internet Explorer.

  - An error in Windows Graphics Component.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5000807");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
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

sysPath = smb_get_system32root();
if(!sysPath)
  exit(0);

dllVer = fetch_file_version(sysPath:sysPath, file_name:"appraiser.dll");
if(!dllVer)
  exit(0);

if(version_in_range(version:dllVer, test_version:"10.0.18362.0", test_version2:"10.0.18362.1014")) {
  report = report_fixed_ver(file_checked:sysPath + "\appraiser.dll",
                            file_version:dllVer, vulnerable_range:"10.0.18362.0 - 10.0.18362.1014");
  security_message(data:report);
  exit(0);
}

exit(99);


