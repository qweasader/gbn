# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818164");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2021-34522", "CVE-2021-34464");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-22 17:06:00 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-08-11 18:23:52 +0530 (Wed, 11 Aug 2021)");
  script_name("Microsoft Windows Defender Multiple RCE Vulnerabilities (Jul 2021)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Security Updates released for Microsoft Windows
  Defender Protection Engine dated 13-07-2021.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple input
  validation errors in Microsoft Windows Defender.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"All versions of Windows");

  script_tag(name:"solution", value:"Run the Windows Update to update the malware
  protection engine to the latest version available. Typically, no action is
  required as the built-in mechanism for the automatic detection and deployment
  of updates will apply the update itself.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34464");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34522");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1,win2012:1, win2012R2:1,
                   win10:1, win10x64:1, win2016:1, win2008:3, win2019:1) <= 0) {
  exit(0);
}

infos = kb_smb_wmi_connectinfo();
if(!infos)
  exit(0);

handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
if(!handle)
  exit(0);

query = "select Name from win32_Service WHERE Name Like '%WinDefend%' and state='Running'";
result = wmi_query(wmi_handle:handle, query:query);
wmi_close(wmi_handle:handle);
if(!result)
  exit(0);

def_version = registry_get_sz(key:"SOFTWARE\Microsoft\Windows Defender\Signature Updates", item:"EngineVersion");
if(!def_version)
  exit(0);

##Microsoft Defender files are still on disk even when disabled. Systems that have disabled Microsoft Defender are not in an exploitable state
##First version of the Microsoft Malware Protection Engine with this vulnerability addressed: Version 1.1.18242.0
if(version_is_less(version:def_version, test_version:"1.1.18242.0")) {
  report = report_fixed_ver(installed_version:def_version, fixed_version:"1.1.18242.0 or higher");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
