# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832366");
  script_version("2023-10-13T05:06:10+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-41039", "CVE-2022-41100", "CVE-2022-41045", "CVE-2022-41109",
                "CVE-2022-41099", "CVE-2022-41098", "CVE-2022-41097", "CVE-2022-41096",
                "CVE-2022-41095", "CVE-2022-41093", "CVE-2022-41092", "CVE-2022-41090",
                "CVE-2022-41088", "CVE-2022-41086", "CVE-2022-41058", "CVE-2022-41057",
                "CVE-2022-41056", "CVE-2022-41055", "CVE-2022-41053", "CVE-2022-41047",
                "CVE-2022-41048", "CVE-2022-38015", "CVE-2022-37992", "CVE-2022-23824",
                "CVE-2022-41128", "CVE-2022-41125", "CVE-2022-41118", "CVE-2022-41073",
                "CVE-2022-41114", "CVE-2022-41054", "CVE-2022-41091", "CVE-2022-41050",
                "CVE-2022-41049", "CVE-2022-41101", "CVE-2022-41102");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-10 14:38:00 +0000 (Thu, 10 Nov 2022)");
  script_tag(name:"creation_date", value:"2023-08-08 12:00:40 +0530 (Tue, 08 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5019980)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5019980");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft ODBC Driver Remote Code Execution Vulnerability.

  - Windows Point-to-Point Tunneling Protocol Remote Code Execution Vulnerability.

  - Windows Pragmatic General Multicast (PGM) Remote Code Execution Vulnerability.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation would allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 11 version 22H2 for x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5019980");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
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

if(hotfix_check_sp(win11:1) <= 0) {
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)) {
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build) {
  exit(0);
}

dllPath = smb_get_systemroot();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"\system32\user32.dll");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.22621.0", test_version2:"10.0.22621.754")) {
  report = report_fixed_ver(file_checked:dllPath + "\system32\user32.dll", file_version:fileVer, vulnerable_range:"10.0.22621.0 - 10.0.22621.754");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);