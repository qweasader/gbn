# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817232");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-1085", "CVE-2020-1267", "CVE-2020-1333", "CVE-2020-1350",
                "CVE-2020-1354", "CVE-2020-1359", "CVE-2020-1360", "CVE-2020-1365",
                "CVE-2020-1371", "CVE-2020-1373", "CVE-2020-1384", "CVE-2020-1389",
                "CVE-2020-1390", "CVE-2020-1396", "CVE-2020-1397", "CVE-2020-1400",
                "CVE-2020-1401", "CVE-2020-1403", "CVE-2020-1407", "CVE-2020-1408",
                "CVE-2020-1409", "CVE-2020-1410", "CVE-2020-1412", "CVE-2020-1419",
                "CVE-2020-1421", "CVE-2020-1427", "CVE-2020-1428", "CVE-2020-1430",
                "CVE-2020-1435", "CVE-2020-1436", "CVE-2020-1437", "CVE-2020-1438",
                "CVE-2020-1468");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-23 19:37:00 +0000 (Thu, 23 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-15 20:23:57 +0530 (Wed, 15 Jul 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4565536)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4565536");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Windows Domain Name System servers fail to properly handle requests (SIGRed, CVE-2020-1350).

  - DirectWrite fails to properly handle objects in memory.

  - Windows Address Book (WAB) fails to properly processes vcard files.

  - Windows Graphics Device Interface (GDI) fails to properly handle
    objects in the memory.

  - Windows Network Connections Service fails to handle objects in memory.

  Please see the references for more information about the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges, disclose sensitive information
  and denial of service attacks.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2008 for 32-bit Systems Service Pack 2

  - Microsoft Windows Server 2008 for x64-based Systems Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4565536");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath)
  exit(0);

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Gdiplus.dll");
if(!fileVer)
  exit(0);

if(version_is_less(version:fileVer, test_version:"5.2.6003.20883")) {
  report = report_fixed_ver(file_checked:dllPath + "\Gdiplus.dll",
                            file_version:fileVer, vulnerable_range:"Less than 5.2.6003.20883");
  security_message(data:report);
  exit(0);
}

exit(99);
