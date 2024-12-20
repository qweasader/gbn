# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813651");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-8282", "CVE-2018-8284", "CVE-2018-0949", "CVE-2018-8125",
                "CVE-2018-8202", "CVE-2018-8206", "CVE-2018-8222", "CVE-2018-8242",
                "CVE-2018-8260", "CVE-2018-8274", "CVE-2018-8275", "CVE-2018-8276",
                "CVE-2018-8279", "CVE-2018-8280", "CVE-2018-8286", "CVE-2018-8287",
                "CVE-2018-8288", "CVE-2018-8290", "CVE-2018-8291", "CVE-2018-8296",
                "CVE-2018-8297", "CVE-2018-8301", "CVE-2018-8304", "CVE-2018-8307",
                "CVE-2018-8308", "CVE-2018-8309", "CVE-2018-8313", "CVE-2018-8324",
                "CVE-2018-8356", "CVE-2016-7279");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-07-11 11:37:54 +0530 (Wed, 11 Jul 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4338825)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4338825");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to errors,

  - When Windows improperly handles File Transfer Protocol (FTP) connections.

  - When Windows improperly handles objects in memory.

  - When the Windows kernel fails to properly handle objects in memory.

  - When Microsoft WordPad improperly handles embedded OLE objects.

  - When Microsoft Edge improperly handles objects in memory.

  - When scripting engine handles objects in memory in Microsoft browsers.

  - When Chakra scripting engine handles objects in memory in Microsoft Edge.

  - When the Windows kernel-mode driver fails to properly handle objects in memory.

  - Microsoft Chakra scripting engine that allows Control Flow Guard (CFG)
    to be bypassed.

  - When Microsoft Internet Explorer improperly handles requests involving UNC
    resources.

  - When Windows Kernel API improperly enforces permissions.

  - A security feature bypass vulnerability exists in Device Guard.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause a target system to stop responding, elevate their privilege level,
  run arbitrary code, bypass security, disclose sensitive information and also
  take control of an affected system.");

  script_tag(name:"affected", value:"- Microsoft Windows 10 Version 1709 for 32-bit Systems

  - Microsoft Windows 10 Version 1709 for 64-based Systems");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4338825");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
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
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.16299.0", test_version2:"11.0.16299.546"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.16299.0 - 11.0.16299.546");
  security_message(data:report);
  exit(0);
}
exit(99);
