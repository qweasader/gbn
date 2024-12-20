# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812877");
  script_version("2023-11-03T16:10:08+0000");
  script_cve_id("CVE-2018-0765", "CVE-2018-1039");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-11-03 16:10:08 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-05-09 14:44:59 +0530 (Wed, 09 May 2018)");
  script_name("Microsoft Windows Server 2012 Multiple Vulnerabilities (KB4096494)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4096494");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist:

  - When .NET and .NET Core improperly process XML documents and

  - In .Net Framework which could allow an attacker to bypass Device Guard.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to cause a denial of service and circumvent a User Mode Code
  Integrity (UMCI) policy on the machine.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2012.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4096494");
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

if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:sysPath, file_name:"mscorlib.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"4.0.30319.36440"))
{
  report = report_fixed_ver(file_checked:sysPath + "\mscorlib.dll",
                            file_version:fileVer, vulnerable_range:"Less than 4.0.30319.36440");
  security_message(data:report);
  exit(0);
}
exit(99);
