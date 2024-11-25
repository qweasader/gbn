# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817269");
  script_version("2024-06-26T05:05:39+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2020-1337", "CVE-2020-1339", "CVE-2020-1377", "CVE-2020-1378",
                "CVE-2020-1379", "CVE-2020-1380", "CVE-2020-1383", "CVE-2020-1464",
                "CVE-2020-1466", "CVE-2020-1467", "CVE-2020-1472", "CVE-2020-1473",
                "CVE-2020-1474", "CVE-2020-1475", "CVE-2020-1477", "CVE-2020-1478",
                "CVE-2020-1485", "CVE-2020-1486", "CVE-2020-1488", "CVE-2020-1489",
                "CVE-2020-1509", "CVE-2020-1513", "CVE-2020-1515", "CVE-2020-1517",
                "CVE-2020-1518", "CVE-2020-1519", "CVE-2020-1520", "CVE-2020-1529",
                "CVE-2020-1530", "CVE-2020-1537", "CVE-2020-1538", "CVE-2020-1554",
                "CVE-2020-1557", "CVE-2020-1558", "CVE-2020-1562", "CVE-2020-1564",
                "CVE-2020-1565", "CVE-2020-1567", "CVE-2020-1570", "CVE-2020-1577",
                "CVE-2020-1579", "CVE-2020-1584", "CVE-2020-1587");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");
  script_tag(name:"creation_date", value:"2020-08-12 14:16:16 +0530 (Wed, 12 Aug 2020)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4571736)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4571736");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error when the Windows Print Spooler service improperly allows
    arbitrary writing to the file system.

  - An error when the Windows Kernel API fails to properly handle
    registry objects in memory.

  - An error when Windows Media Foundation fails to properly handle
    objects in memory.

  - An error in the way that the scripting engine handles objects
    in the memory in Internet Explorer.

  - An error in RPC if the server has Routing and Remote Access enabled.

  Please see the references for more information on the vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, elevate privileges and disclose sensitive information.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4571736");
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

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

dllPath = smb_get_system32root();
if(!dllPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:dllPath, file_name:"Localspl.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.2.9200.23121"))
{
  report = report_fixed_ver(file_checked:dllPath + "\Localspl.dll",
                            file_version:fileVer, vulnerable_range:"Less than 6.2.9200.23121");
  security_message(data:report);
  exit(0);
}
exit(99);
