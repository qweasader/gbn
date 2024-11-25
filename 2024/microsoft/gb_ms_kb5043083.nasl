# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834483");
  script_version("2024-09-18T07:47:18+0000");
  script_cve_id("CVE-2024-38249", "CVE-2024-43491", "CVE-2024-43487", "CVE-2024-30073",
                "CVE-2024-43461", "CVE-2024-38119", "CVE-2024-38247", "CVE-2024-38245",
                "CVE-2024-38244", "CVE-2024-38243", "CVE-2024-38239", "CVE-2024-38238",
                "CVE-2024-38237", "CVE-2024-38235", "CVE-2024-38234", "CVE-2024-38217",
                "CVE-2024-38046", "CVE-2024-38014", "CVE-2024-38256", "CVE-2024-38254",
                "CVE-2024-38250", "CVE-2024-38242", "CVE-2024-38241", "CVE-2024-38240");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-18 07:47:18 +0000 (Wed, 18 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-10 17:15:36 +0000 (Tue, 10 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-09-11 11:42:59 +0530 (Wed, 11 Sep 2024)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB5043083)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB5043083");

  script_tag(name:"insight", value:"These vulnerabilities exist:

  - CVE-2024-38119: Windows Network Address Translation (NAT) Remote Code Execution Vulnerability

  - CVE-2024-38254: Windows Authentication Information Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation allows an attacker
  to elevate privileges, execute arbitrary commands, disclose information,
  bypass security restrictions, conduct spoofing and denial of service
  attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 for 32-bit Systems

  - Microsoft Windows 10 for x64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5043083");
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

dllPath = smb_get_system32root();
if(!dllPath ) {
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"ntoskrnl.exe");
if(!fileVer) {
  exit(0);
}

if(version_in_range(version:fileVer, test_version:"10.0.10240.0", test_version2:"10.0.10240.20760")) {
  report = report_fixed_ver(file_checked:dllPath + "\Ntoskrnl.exe", file_version:fileVer, vulnerable_range:"10.0.10240.0 - 10.0.10240.20760");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
