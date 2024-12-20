# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812678");
  script_version("2023-07-20T05:05:18+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:18 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2018-01-29 16:17:29 +0530 (Mon, 29 Jan 2018)");
  script_name("Spectre Variant 2 (CVE 2017-5715) Branch Target Injection Update Disable (KB4078130)");

  script_tag(name:"summary", value:"This host is missing a critical update
  according to Microsoft KB4078130");

  script_tag(name:"vuldetect", value:"Check if the Spectre Variant 2 update is
  disabled or not.");

  script_tag(name:"insight", value:"Intel has reported issues with recently
  released microcode meant to address Spectre variant 2 (CVE 2017-5715 Branch
  Target Injection)  specifically Intel noted that this microcode can cause
  'higher than expected reboots and other unpredictable system behavior'. On
  January 22, 2018 Intel recommended that customers stop deploying the current
  microcode version on impacted processors while they perform additional testing
  on the updated solution. While Intel tests, updates and deploys new microcode,
  Microsoft is providing update KB4078130 that specifically disables only the
  mitigation against CVE-2017-5715  'Branch target injection vulnerability'.
  This update has been found to prevent the behavior described.");

  script_tag(name:"impact", value:"Installing and enabling update for Spectre
  Variant 2 may result in 'data loss or corruption'. Also system instability can
  in some circumstances cause data loss or corruption.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2016

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows 10

  - Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4078130");
  script_xref(name:"URL", value:"https://newsroom.intel.com/news/root-cause-of-reboot-issue-identified-updated-guidance-for-customers-and-partners");

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

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8_1:1, win8_1x64:1, win2012R2:1,
                   win2008:3, win2008x64:3, win2016:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

key = "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" ;

override = registry_get_dword(key:key, item:"FeatureSettingsOverride");
overridemask = registry_get_dword(key:key, item:"FeatureSettingsOverrideMask");

if(!override || !overridemask)
  exit(0);

if((override == 1 && overridemask == 1)|| (override == 3 && overridemask == 3)){
  exit(0);
} else if((override == 0 && overridemask == 1) || (override == 0 && overridemask == 3))
{
  report = report_fixed_ver(installed_version: "Spectre Variant 2 Mitigation Enabled", fixed_version: "Disable Spectre Variant 2 Mitigation");
  security_message(data:report);
  exit(0);
}
exit(0);
