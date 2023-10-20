# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.832378");
  script_version("2023-10-13T05:06:10+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-38172", "CVE-2023-38184", "CVE-2023-38186", "CVE-2023-35387",
                "CVE-2023-35386", "CVE-2023-35385", "CVE-2023-35384", "CVE-2023-35383",
                "CVE-2023-35380", "CVE-2023-35378", "CVE-2023-35377", "CVE-2023-38254",
                "CVE-2023-36913", "CVE-2023-36911", "CVE-2023-36907", "CVE-2023-36889",
                "CVE-2023-35382", "CVE-2023-35381", "CVE-2023-35376", "CVE-2023-36914",
                "CVE-2023-36912", "CVE-2023-36910", "CVE-2023-36909", "CVE-2023-36908",
                "CVE-2023-36906", "CVE-2023-36905", "CVE-2023-36904", "CVE-2023-36903",
                "CVE-2023-20569", "CVE-2023-36900", "CVE-2023-36882", "CVE-2023-35359",
                "CVE-2023-36884");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-10 21:07:00 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-09 10:40:13 +0530 (Wed, 09 Aug 2023)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5029244)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5029244");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A Remote Code Execution Vulnerability in Windows Lightweight Directory Access Protocol (LDAP).

  - An Elevation of Privilege Vulnerability in Windows Mobile Device Management.

  - An Information Disclosure Vulnerability in Microsoft Message Queuing.

  For more information about the vulnerabilities refer to Reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to elevate privileges, execute arbitrary commands, bypass security
  feature, disclose information and conduct DoS attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 21H2 for 32-bit Systems

  - Microsoft Windows 10 Version 21H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for x64-based Systems

  - Microsoft Windows 10 Version 22H2 for 32-bit Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5029244");
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

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);

}
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
if(!registry_key_exists(key:key)){
  exit(0);
}

build = registry_get_sz(key:key, item:"CurrentBuild");
if(!build){
  exit(0);
}

if(!("19042" >< build || "19044" >< build || "19045" >< build)){
  exit(0);
}
dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"10.0.19041.3324")) {
  report = report_fixed_ver(file_checked:dllPath + "\ntoskrnl.exe", file_version:fileVer, vulnerable_range:"Less than 10.0.19041.3324");

  security_message(port:0, data:report);
  exit(0);
}

exit(99);
