# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817640");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2020-17123", "CVE-2020-17125", "CVE-2020-17126", "CVE-2020-17128",
                "CVE-2020-17129", "CVE-2020-17130", "CVE-2020-17119", "CVE-2020-17124");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-03 21:43:00 +0000 (Wed, 03 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-12-09 08:38:43 +0530 (Wed, 09 Dec 2020)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities (Dec 2020)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to multiple errors in excel,
  outlook and powerpoint.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, bypass security restrictions and gain access to sensitive data.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");
  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
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

## Version 2011 (Build 13426.20332)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13426.20332")){
    fix = "2011 (Build 13426.20332)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## 2008 (Build 13127.20910)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.20910")){
    fix = "2008 (Build 13127.20910)";
  }
}

## 1908 (Build 11929.20984)
## 2002 (Build 12527.21416)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11929.20984")){
    fix = "1908 (Build 11929.20984)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.12527", test_version2:"16.0.12527.21415")){
    fix = "2002 (Build 12527.21416)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);
