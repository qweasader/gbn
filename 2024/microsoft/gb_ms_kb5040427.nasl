# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834222");
  script_version("2024-08-23T05:05:37+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-38027", "CVE-2024-37989", "CVE-2024-37988", "CVE-2024-38069",
                "CVE-2024-38068", "CVE-2024-38050", "CVE-2024-38047", "CVE-2024-38033",
                "CVE-2024-38079", "CVE-2024-38070", "CVE-2024-38052", "CVE-2024-38030",
                "CVE-2024-38057", "CVE-2024-37984", "CVE-2024-38105", "CVE-2024-38049",
                "CVE-2024-38028", "CVE-2024-38053", "CVE-2024-38066", "CVE-2024-38017",
                "CVE-2024-39684", "CVE-2024-38065", "CVE-2024-38058", "CVE-2024-38010",
                "CVE-2024-38101", "CVE-2024-38032", "CVE-2024-37973", "CVE-2024-38019",
                "CVE-2024-38048", "CVE-2024-38011", "CVE-2024-37975", "CVE-2024-37972",
                "CVE-2024-37971", "CVE-2024-3596", "CVE-2024-30079", "CVE-2024-30071",
                "CVE-2024-30013", "CVE-2024-26184", "CVE-2024-38112", "CVE-2024-38104",
                "CVE-2024-38102", "CVE-2024-38091", "CVE-2024-38085", "CVE-2024-38064",
                "CVE-2024-38062", "CVE-2024-38061", "CVE-2024-38060", "CVE-2024-38059",
                "CVE-2024-38056", "CVE-2024-38055", "CVE-2024-38054", "CVE-2024-38051",
                "CVE-2024-38517", "CVE-2024-38043", "CVE-2024-38041", "CVE-2024-38034",
                "CVE-2024-38025", "CVE-2024-38022", "CVE-2024-38013", "CVE-2024-37987",
                "CVE-2024-37986", "CVE-2024-37981", "CVE-2024-37974", "CVE-2024-37970",
                "CVE-2024-37969", "CVE-2024-35270", "CVE-2024-30098", "CVE-2024-30081",
                "CVE-2024-28899", "CVE-2024-21417", "CVE-2024-38161", "CVE-2024-38184",
                "CVE-2024-38191", "CVE-2024-38187", "CVE-2024-38186", "CVE-2024-38185");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-08-23 05:05:37 +0000 (Fri, 23 Aug 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-09 17:15:47 +0000 (Tue, 09 Jul 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 10:01:10 +0530 (Wed, 10 Jul 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5040427)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5040427");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-38027: Windows Line Printer Daemon Service Denial of Service Vulnerability

  - CVE-2024-37989: Secure Boot Security Feature Bypass Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, spoofing and conduct denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5040427");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0) {
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

if(!("19044" >< build || "19045" >< build)) {
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.19041.4648")) {
  report = report_fixed_ver(file_checked:dllPath + "\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.19041.4648");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
