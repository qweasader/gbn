# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826938");
  script_version("2023-03-24T10:19:42+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-23397", "CVE-2023-23398", "CVE-2023-23399");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-15 11:40:32 +0530 (Wed, 15 Mar 2023)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities - Mar23");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run update March 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An incorrect processing of user-supplied data in Microsoft Excel.

  - An insufficient validation of user-supplied input in Microsoft Excel.

  - An unspecified elevation of privilege vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code, elevate privileges and conduct spoofing attack on
  an affected system.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## Version 2302 (Build 16130.20306)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.16130.20306")){
    fix = "Version 2302 (Build 16130.20306)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2301 (Build 16130.20306)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.16130.20306")){
    fix = "Version 2301 (Build 16130.20306)";
  }
}

## Semi-Annual Enterprise Channel: Version 2202 (Build 14931.20944)
## Semi-Annual Enterprise Channel: Version 2208 (Build 15601.20578)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14931.20944")){
    fix = "Version 2202 (Build 14931.20944)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.15601.0", test_version2:"16.0.15601.20577")){
    fix = "Version 2208 (Build 15601.20578)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
