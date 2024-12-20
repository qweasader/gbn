# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811556");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-1438");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-31 17:43:00 +0000 (Mon, 31 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-08-07 12:12:24 +0530 (Mon, 07 Aug 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Panda Kernel Memory Access Driver Code Execution Vulnerability");

  script_tag(name:"summary", value:"Panda Security products is prone to a code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient
  validation of user-supplied input to the PSKMAD.sys kernel driver implemented in the
  affected products.");

  script_tag(name:"impact", value:"Successful exploitation will allow the
  an authenticated, local attacker to pass malicious input to the affected
  driver. If processed, an attacker could execute arbitrary code with kernel-level
  privileges.");

  script_tag(name:"affected", value:"Panda Gold Protection 2015 PSKMAD.sys version 1.0.0.13

  Panda Global Protection 2015 PSKMAD.sys version1.0.0.13

  Panda Internet Security 2015 PSKMAD.sys version 1.0.0.13

  Panda Antivirus Pro 2015 PSKMAD.sys version 1.0.0.13.");

  script_tag(name:"solution", value:"Upgrade to Panda Products version 15.1.0
  or later or apply the safeguards as mentioned below.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132682");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/75715");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jul/42");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2015-1438");
  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=39908");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.pandasecurity.com");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Panda Software") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Panda Software")){
  exit(0);
}

if("x86" >< os_arch){
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Panda Universal Agent Endpoint";
}

## Currently 64 bit app is not available for download
else if("x64" >< os_arch){
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Panda Universal Agent Endpoint";
}

if(!registry_key_exists(key:key)){
  exit(0);
}

pandaurlPath = registry_get_sz(item:"InstallLocation", key:key);
if(!pandaurlPath){
  exit(0);
}

pskmadVer = fetch_file_version(sysPath:pandaurlPath,
                                  file_name: "\pskmad.sys");

## Detecting vulnerability on 2015 products, based on pskmad.sys version
if(pskmadVer == "1.0.0.13")
{
  report = report_fixed_ver(installed_version:"PSKMAD.sys kernel driver version" + pskmadVer, fixed_version:"Upgrade to Product's Version 15.1.0");
  security_message(data:report);
  exit(0);
}

exit(99);
